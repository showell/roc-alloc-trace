// roc-alloc-trace: counts a Roc program's allocations, and finds its copies,
// by breakpoints in the very executable you ship. Linux x86-64.
//
//   roc-alloc-trace count [--small N] [--big M] [--timeout S] -- PROGRAM ARG...
//   roc-alloc-trace where [--small N] [--big M] [--timeout S] [--tsv FILE] -- PROGRAM ARG...
//   roc-alloc-trace where [--tsv FILE] [--only PREFIX] CHECKFILE
//   roc-alloc-trace check [--report] [--only PREFIX] CHECKFILE
//
// `{N}` in an argument is the iteration count: the program runs once with
// N = --small (1000) and once with N = --big (10000), and what one more
// iteration costs is the difference over M - N. README.md says what each
// mode prints, and the check file's format.
//
// Build: cc -O2 -o roc-alloc-trace roc-alloc-trace.c
//
// **HOW IT COUNTS.** Every allocation a Roc program makes goes through the
// platform's roc_alloc (and roc_realloc to grow one). The program runs under
// ptrace with an int3 at each such function's first instruction; each stop
// is a call. For `where`, every builtin of the executable's symbol table
// gets a breakpoint too: Roc writes into a list in place when its refcount
// is 1 and otherwise copies it, and the copy is a roc_alloc made inside the
// builtin. An allocation whose return address is in no Roc procedure was
// made by builtin code, and is put down to the last builtin entered from
// Roc code, at the call site (and the frame-pointer chain above it) where
// Roc code entered it. Names and lines come from the executable's own
// symbol table and DWARF, read here.

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TOOL "roc-alloc-trace"

// Exit codes: 0 on track, 1 a count off its expected value, 2 anything that
// stopped the measurement (a refused program, a run that failed, a bad file).
enum { EXIT_OFF = 1, EXIT_FAIL = 2 };

static void fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, TOOL ": ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(EXIT_FAIL);
}

static void *must_alloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    if (p == NULL) fail("out of memory");
    return p;
}

static void *must_grow(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (q == NULL) fail("out of memory");
    return q;
}

static char *must_dup(const char *s) {
    char *d = strdup(s);
    if (d == NULL) fail("out of memory");
    return d;
}

static int starts_with(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

// ─── The executable: its ELF header, symbols and sections ────────────────

typedef struct {
    const char *name;
    uint64_t value, size;
    int func;
} Sym;

typedef struct {
    const uint8_t *data;
    size_t size;
} Section;

typedef struct {
    char *path;
    const uint8_t *data;
    size_t size;
    const Elf64_Ehdr *eh;
    Sym *syms;
    size_t nsyms;
    Section debug_info, debug_abbrev, debug_line, debug_str, debug_line_str, debug_ranges, debug_rnglists,
        debug_addr, debug_str_offsets;
} Exe;

static Section section_named(const Exe *x, const char *want) {
    Section s = {NULL, 0};
    const Elf64_Ehdr *eh = x->eh;
    if (eh->e_shoff == 0 || eh->e_shstrndx == SHN_UNDEF) return s;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(x->data + eh->e_shoff);
    const char *names = (const char *)(x->data + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (strcmp(names + sh[i].sh_name, want) == 0 && sh[i].sh_type != SHT_NOBITS) {
            if (sh[i].sh_offset + sh[i].sh_size > x->size) fail("%s: section %s runs past the file", x->path, want);
            s.data = x->data + sh[i].sh_offset;
            s.size = sh[i].sh_size;
        }
    }
    return s;
}

static Exe *exe_open(const char *path) {
    Exe *x = must_alloc(sizeof *x);
    x->path = must_dup(path);
    int fd = open(path, O_RDONLY);
    if (fd < 0) fail("%s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0) fail("%s: %s", path, strerror(errno));
    x->size = (size_t)st.st_size;
    if (x->size < sizeof(Elf64_Ehdr)) fail("%s: not an ELF executable", path);
    void *m = mmap(NULL, x->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) fail("%s: %s", path, strerror(errno));
    close(fd);
    x->data = m;
    x->eh = m;
    const Elf64_Ehdr *eh = x->eh;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) fail("%s: not an ELF executable", path);
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_X86_64)
        fail("%s: not an x86-64 executable; " TOOL " runs on Linux x86-64 only", path);
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) fail("%s: not an executable", path);
    if (eh->e_shoff == 0) fail("%s: has no section headers, so no symbol table", path);
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(x->data + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB) continue;
        const Elf64_Sym *es = (const Elf64_Sym *)(x->data + sh[i].sh_offset);
        size_t n = sh[i].sh_size / sizeof(Elf64_Sym);
        const char *strs = (const char *)(x->data + sh[sh[i].sh_link].sh_offset);
        x->syms = must_alloc(n * sizeof(Sym));
        for (size_t k = 0; k < n; k++) {
            int type = ELF64_ST_TYPE(es[k].st_info);
            if (es[k].st_shndx == SHN_UNDEF || es[k].st_name == 0) continue;
            if (type == STT_FILE || type == STT_SECTION) continue;
            x->syms[x->nsyms++] = (Sym){strs + es[k].st_name, es[k].st_value, es[k].st_size, type == STT_FUNC};
        }
    }
    if (x->nsyms == 0) fail("%s: has no symbol table (stripped?); " TOOL " finds roc_alloc by name", path);
    x->debug_info = section_named(x, ".debug_info");
    x->debug_abbrev = section_named(x, ".debug_abbrev");
    x->debug_line = section_named(x, ".debug_line");
    x->debug_str = section_named(x, ".debug_str");
    x->debug_line_str = section_named(x, ".debug_line_str");
    x->debug_ranges = section_named(x, ".debug_ranges");
    x->debug_rnglists = section_named(x, ".debug_rnglists");
    x->debug_addr = section_named(x, ".debug_addr");
    x->debug_str_offsets = section_named(x, ".debug_str_offsets");
    return x;
}

static const Sym *sym_named(const Exe *x, const char *name) {
    for (size_t i = 0; i < x->nsyms; i++) {
        if (strcmp(x->syms[i].name, name) == 0 && x->syms[i].size > 0) return &x->syms[i];
    }
    return NULL;
}

// The file's bytes at a virtual address, as the loader maps them: up to
// `want` bytes, fewer at a segment's end, 0 for an address no segment loads.
static size_t file_bytes_at(const Exe *x, uint64_t vaddr, uint8_t *out, size_t want) {
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(x->data + x->eh->e_phoff);
    for (int i = 0; i < x->eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (vaddr < ph[i].p_vaddr || vaddr >= ph[i].p_vaddr + ph[i].p_filesz) continue;
        size_t n = (size_t)(ph[i].p_vaddr + ph[i].p_filesz - vaddr);
        if (n > want) n = want;
        memcpy(out, x->data + ph[i].p_offset + (vaddr - ph[i].p_vaddr), n);
        return n;
    }
    return 0;
}

// The function symbol whose code holds `vaddr`, for an address no DWARF
// function covers.
static const Sym *func_sym_at(const Exe *x, uint64_t vaddr) {
    const Sym *best = NULL;
    for (size_t i = 0; i < x->nsyms; i++) {
        const Sym *s = &x->syms[i];
        if (!s->func || s->size == 0) continue;
        if (vaddr >= s->value && vaddr < s->value + s->size && (best == NULL || s->size < best->size)) best = s;
    }
    return best;
}

// ─── DWARF: a reader for the parts used here ─────────────────────────────
//
// .debug_info gives each procedure's Roc name (DW_AT_name beside its
// DW_AT_linkage_name, the symbol) and the functions that cover an address;
// .debug_line gives an address's file and line. Versions 2 to 5.

typedef struct {
    const uint8_t *p, *end;
    int bad;
} Cur;

static uint64_t rd_n(Cur *c, int n) {
    if (c->p + n > c->end) {
        c->bad = 1;
        c->p = c->end;
        return 0;
    }
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)c->p[i] << (8 * i);
    c->p += n;
    return v;
}

static uint64_t rd_uleb(Cur *c) {
    uint64_t v = 0;
    int shift = 0;
    while (c->p < c->end) {
        uint8_t b = *c->p++;
        if (shift < 64) v |= (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if ((b & 0x80) == 0) return v;
    }
    c->bad = 1;
    return v;
}

static int64_t rd_sleb(Cur *c) {
    int64_t v = 0;
    int shift = 0;
    uint8_t b = 0;
    while (c->p < c->end) {
        b = *c->p++;
        if (shift < 64) v |= (int64_t)(b & 0x7f) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 64 && (b & 0x40)) v |= -((int64_t)1 << shift);
    return v;
}

static const char *rd_str(Cur *c) {
    const char *s = (const char *)c->p;
    while (c->p < c->end && *c->p) c->p++;
    if (c->p >= c->end) {
        c->bad = 1;
        return "";
    }
    c->p++;
    return s;
}

static const char *str_at(const Section *s, uint64_t off) {
    if (s->data == NULL || off >= s->size) return NULL;
    return (const char *)s->data + off;
}

// One function a DIE describes: the procedure's symbol and Roc name, and
// the code it covers.
typedef struct {
    uint64_t lo, hi;
    const char *name;   // DW_AT_linkage_name when it has one, else DW_AT_name
} FnRange;

typedef struct {
    uint64_t offset;    // the DIE's offset in .debug_info
    const char *name, *linkage;
} DieName;

typedef struct {
    uint64_t lo, hi;
    const char *file;
    uint64_t line;
} LineRange;

typedef struct {
    const char *symbol, *name;
} NamePair;

typedef struct {
    NamePair *names;    // linkage name to Roc name, sorted by symbol
    size_t nnames;
    FnRange *fns;
    size_t nfns, capfns;
    LineRange *lines;   // sorted by lo
    size_t nlines, caplines;
} Debug;

typedef struct {
    uint64_t name, form;
    int64_t implicit;
} AttrSpec;

typedef struct {
    uint64_t code, tag;
    int children;
    AttrSpec *attrs;
    size_t nattrs;
} Abbrev;

typedef struct {
    Abbrev *items;
    size_t n;
} Abbrevs;

static Abbrevs read_abbrevs(const Exe *x, uint64_t off) {
    Abbrevs a = {NULL, 0};
    size_t cap = 0;
    Cur c = {x->debug_abbrev.data + off, x->debug_abbrev.data + x->debug_abbrev.size, 0};
    if (off >= x->debug_abbrev.size) return a;
    for (;;) {
        uint64_t code = rd_uleb(&c);
        if (code == 0 || c.bad) break;
        if (a.n == cap) {
            cap = cap ? cap * 2 : 64;
            a.items = must_grow(a.items, cap * sizeof(Abbrev));
        }
        Abbrev *ab = &a.items[a.n++];
        memset(ab, 0, sizeof *ab);
        ab->code = code;
        ab->tag = rd_uleb(&c);
        ab->children = (int)rd_n(&c, 1);
        size_t acap = 0;
        for (;;) {
            uint64_t name = rd_uleb(&c), form = rd_uleb(&c);
            int64_t implicit = 0;
            if (form == 0x21) implicit = rd_sleb(&c);
            if ((name == 0 && form == 0) || c.bad) break;
            if (ab->nattrs == acap) {
                acap = acap ? acap * 2 : 8;
                ab->attrs = must_grow(ab->attrs, acap * sizeof(AttrSpec));
            }
            ab->attrs[ab->nattrs++] = (AttrSpec){name, form, implicit};
        }
    }
    return a;
}

static const Abbrev *abbrev_of(const Abbrevs *a, uint64_t code) {
    if (code >= 1 && code <= a->n && a->items[code - 1].code == code) return &a->items[code - 1];
    for (size_t i = 0; i < a->n; i++) {
        if (a->items[i].code == code) return &a->items[i];
    }
    return NULL;
}

// The unit's header fields an attribute's value depends on.
typedef struct {
    int version, addr_size, offset_size;
    uint64_t unit_offset;
    uint64_t str_offsets_base, addr_base, rnglists_base;
    uint64_t base_pc;
} Unit;

enum { V_NONE, V_UINT, V_STR, V_REF, V_STRX, V_ADDRX, V_SEC, V_RNGLISTX };

typedef struct {
    int kind;
    uint64_t u;
    const char *s;
    uint64_t form;
} Val;

// One attribute's value read, and its bytes passed.
static Val read_form(const Exe *x, Cur *c, const Unit *u, uint64_t form, int64_t implicit) {
    Val v = {V_UINT, 0, NULL, form};
    switch (form) {
    case 0x01: v.u = rd_n(c, u->addr_size); break;                       // addr
    case 0x03: c->p += rd_n(c, 2); v.kind = V_NONE; break;                // block2
    case 0x04: c->p += rd_n(c, 4); v.kind = V_NONE; break;                // block4
    case 0x05: v.u = rd_n(c, 2); break;                                  // data2
    case 0x06: v.u = rd_n(c, 4); break;                                  // data4
    case 0x07: v.u = rd_n(c, 8); break;                                  // data8
    case 0x1e: c->p += 16; v.kind = V_NONE; break;                        // data16
    case 0x08: v.kind = V_STR; v.s = rd_str(c); break;                    // string
    case 0x09: case 0x18: c->p += rd_uleb(c); v.kind = V_NONE; break;     // block, exprloc
    case 0x0a: c->p += rd_n(c, 1); v.kind = V_NONE; break;                // block1
    case 0x0b: v.u = rd_n(c, 1); break;                                  // data1
    case 0x0c: v.u = rd_n(c, 1); break;                                  // flag
    case 0x0d: v.u = (uint64_t)rd_sleb(c); break;                        // sdata
    case 0x0e: v.kind = V_STR; v.s = str_at(&x->debug_str, rd_n(c, u->offset_size)); break;       // strp
    case 0x1f: v.kind = V_STR; v.s = str_at(&x->debug_line_str, rd_n(c, u->offset_size)); break;  // line_strp
    case 0x1d: case 0x1f21: rd_n(c, u->offset_size); v.kind = V_NONE; break;                      // strp_sup
    case 0x0f: v.u = rd_uleb(c); break;                                  // udata
    case 0x10: v.kind = V_REF; v.u = rd_n(c, u->version <= 2 ? u->addr_size : u->offset_size); break;  // ref_addr
    case 0x11: v.kind = V_REF; v.u = u->unit_offset + rd_n(c, 1); break;
    case 0x12: v.kind = V_REF; v.u = u->unit_offset + rd_n(c, 2); break;
    case 0x13: v.kind = V_REF; v.u = u->unit_offset + rd_n(c, 4); break;
    case 0x14: v.kind = V_REF; v.u = u->unit_offset + rd_n(c, 8); break;
    case 0x15: v.kind = V_REF; v.u = u->unit_offset + rd_uleb(c); break;
    case 0x1c: rd_n(c, 4); v.kind = V_NONE; break;                        // ref_sup4
    case 0x24: rd_n(c, 8); v.kind = V_NONE; break;                        // ref_sup8
    case 0x20: rd_n(c, 8); v.kind = V_NONE; break;                        // ref_sig8
    case 0x1f20: rd_n(c, u->offset_size); v.kind = V_NONE; break;         // GNU_ref_alt
    case 0x17: v.kind = V_SEC; v.u = rd_n(c, u->offset_size); break;      // sec_offset
    case 0x19: v.u = 1; break;                                           // flag_present
    case 0x21: v.u = (uint64_t)implicit; break;                          // implicit_const
    case 0x1a: case 0x1f02: v.kind = V_STRX; v.u = rd_uleb(c); break;     // strx
    case 0x25: v.kind = V_STRX; v.u = rd_n(c, 1); break;
    case 0x26: v.kind = V_STRX; v.u = rd_n(c, 2); break;
    case 0x27: v.kind = V_STRX; v.u = rd_n(c, 3); break;
    case 0x28: v.kind = V_STRX; v.u = rd_n(c, 4); break;
    case 0x1b: case 0x1f01: v.kind = V_ADDRX; v.u = rd_uleb(c); break;    // addrx
    case 0x29: v.kind = V_ADDRX; v.u = rd_n(c, 1); break;
    case 0x2a: v.kind = V_ADDRX; v.u = rd_n(c, 2); break;
    case 0x2b: v.kind = V_ADDRX; v.u = rd_n(c, 3); break;
    case 0x2c: v.kind = V_ADDRX; v.u = rd_n(c, 4); break;
    case 0x22: v.kind = V_NONE; rd_uleb(c); break;                        // loclistx
    case 0x23: v.kind = V_RNGLISTX; v.u = rd_uleb(c); break;              // rnglistx
    case 0x16: {                                                         // indirect
        uint64_t f = rd_uleb(c);
        return read_form(x, c, u, f, 0);
    }
    default:
        c->bad = 1;
        v.kind = V_NONE;
    }
    if (c->p > c->end) {
        c->p = c->end;
        c->bad = 1;
    }
    return v;
}

static const char *val_str(const Exe *x, const Unit *u, const Val *v) {
    if (v->kind == V_STR) return v->s;
    if (v->kind == V_STRX && x->debug_str_offsets.data != NULL) {
        uint64_t at = u->str_offsets_base + v->u * (uint64_t)u->offset_size;
        if (at + (uint64_t)u->offset_size > x->debug_str_offsets.size) return NULL;
        Cur c = {x->debug_str_offsets.data + at, x->debug_str_offsets.data + x->debug_str_offsets.size, 0};
        return str_at(&x->debug_str, rd_n(&c, u->offset_size));
    }
    return NULL;
}

static int val_addr(const Exe *x, const Unit *u, const Val *v, uint64_t *out) {
    if (v->kind == V_UINT && v->form == 0x01) {
        *out = v->u;
        return 1;
    }
    if (v->kind == V_ADDRX && x->debug_addr.data != NULL) {
        uint64_t at = u->addr_base + v->u * (uint64_t)u->addr_size;
        if (at + (uint64_t)u->addr_size > x->debug_addr.size) return 0;
        Cur c = {x->debug_addr.data + at, x->debug_addr.data + x->debug_addr.size, 0};
        *out = rd_n(&c, u->addr_size);
        return 1;
    }
    return 0;
}

static void add_fn(Debug *d, uint64_t lo, uint64_t hi, const char *name) {
    if (hi <= lo || name == NULL) return;
    if (d->nfns == d->capfns) {
        d->capfns = d->capfns ? d->capfns * 2 : 1024;
        d->fns = must_grow(d->fns, d->capfns * sizeof(FnRange));
    }
    d->fns[d->nfns++] = (FnRange){lo, hi, name};
}

// The ranges a DW_AT_ranges value names, each added as the function `name`.
static void add_ranges(const Exe *x, Debug *d, const Unit *u, const Val *v, const char *name) {
    if (u->version <= 4) {
        if (x->debug_ranges.data == NULL || v->u >= x->debug_ranges.size) return;
        Cur c = {x->debug_ranges.data + v->u, x->debug_ranges.data + x->debug_ranges.size, 0};
        uint64_t base = u->base_pc;
        while (!c.bad) {
            uint64_t a = rd_n(&c, u->addr_size), b = rd_n(&c, u->addr_size);
            if (a == 0 && b == 0) break;
            if (a == UINT64_MAX) {
                base = b;
                continue;
            }
            add_fn(d, base + a, base + b, name);
        }
        return;
    }
    if (x->debug_rnglists.data == NULL) return;
    uint64_t off = v->u;
    if (v->kind == V_RNGLISTX) {
        uint64_t at = u->rnglists_base + v->u * (uint64_t)u->offset_size;
        if (at + (uint64_t)u->offset_size > x->debug_rnglists.size) return;
        Cur ic = {x->debug_rnglists.data + at, x->debug_rnglists.data + x->debug_rnglists.size, 0};
        off = u->rnglists_base + rd_n(&ic, u->offset_size);
    }
    if (off >= x->debug_rnglists.size) return;
    Cur c = {x->debug_rnglists.data + off, x->debug_rnglists.data + x->debug_rnglists.size, 0};
    uint64_t base = u->base_pc;
    while (!c.bad) {
        uint8_t kind = (uint8_t)rd_n(&c, 1);
        if (kind == 0) break;
        Val ax = {V_ADDRX, 0, NULL, 0x1b};
        uint64_t a = 0, b = 0;
        switch (kind) {
        case 1: ax.u = rd_uleb(&c); val_addr(x, u, &ax, &base); break;   // base_addressx
        case 2:                                                          // startx_endx
            ax.u = rd_uleb(&c); val_addr(x, u, &ax, &a);
            ax.u = rd_uleb(&c); val_addr(x, u, &ax, &b);
            add_fn(d, a, b, name);
            break;
        case 3:                                                          // startx_length
            ax.u = rd_uleb(&c); val_addr(x, u, &ax, &a);
            add_fn(d, a, a + rd_uleb(&c), name);
            break;
        case 4: a = rd_uleb(&c); b = rd_uleb(&c); add_fn(d, base + a, base + b, name); break;  // offset_pair
        case 5: base = rd_n(&c, u->addr_size); break;                    // base_address
        case 6: a = rd_n(&c, u->addr_size); b = rd_n(&c, u->addr_size); add_fn(d, a, b, name); break;
        case 7: a = rd_n(&c, u->addr_size); add_fn(d, a, a + rd_uleb(&c), name); break;
        default: return;
        }
    }
}

static int compare_dienames(const void *a, const void *b) {
    const DieName *x = a, *y = b;
    return x->offset < y->offset ? -1 : x->offset > y->offset;
}

static const DieName *diename_at(const DieName *all, size_t n, uint64_t offset) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (all[mid].offset < offset) lo = mid + 1;
        else hi = mid;
    }
    return lo < n && all[lo].offset == offset ? &all[lo] : NULL;
}

// A function DIE whose name is its abstract origin's or specification's,
// resolved once every DIE has been read.
typedef struct {
    uint64_t lo, hi;
    int has_pc;
    uint64_t origin;
    Val ranges;
    int has_ranges;
    Unit unit;
} Pending;

static int compare_names(const void *a, const void *b) {
    return strcmp(((const NamePair *)a)->symbol, ((const NamePair *)b)->symbol);
}

static void read_info(const Exe *x, Debug *d) {
    const Section *info = &x->debug_info;
    if (info->data == NULL || x->debug_abbrev.data == NULL) return;
    DieName *dn = NULL;
    size_t ndn = 0, capdn = 0;
    Pending *pend = NULL;
    size_t npend = 0, cappend = 0;
    size_t capnames = 0;
    uint64_t off = 0;
    while (off + 11 <= info->size) {
        Cur c = {info->data + off, info->data + info->size, 0};
        Unit u;
        memset(&u, 0, sizeof u);
        u.unit_offset = off;
        uint64_t len = rd_n(&c, 4);
        u.offset_size = 4;
        if (len == 0xffffffff) {
            len = rd_n(&c, 8);
            u.offset_size = 8;
        }
        const uint8_t *unit_end = c.p + len;
        if (unit_end > c.end || len == 0) break;
        c.end = unit_end;
        u.version = (int)rd_n(&c, 2);
        uint64_t abbrev_off;
        if (u.version >= 5) {
            int unit_type = (int)rd_n(&c, 1);
            u.addr_size = (int)rd_n(&c, 1);
            abbrev_off = rd_n(&c, u.offset_size);
            if (unit_type == 4 || unit_type == 5) rd_n(&c, 8);                   // skeleton, split_compile
            if (unit_type == 2 || unit_type == 6) {                              // type, split_type
                rd_n(&c, 8);
                rd_n(&c, u.offset_size);
            }
        } else {
            abbrev_off = rd_n(&c, u.offset_size);
            u.addr_size = (int)rd_n(&c, 1);
        }
        uint64_t next = (uint64_t)(unit_end - info->data);
        if (u.version < 2 || u.version > 5 || u.addr_size != 8) {
            off = next;
            continue;
        }
        Abbrevs ab = read_abbrevs(x, abbrev_off);
        while (c.p < c.end && !c.bad) {
            uint64_t die_off = (uint64_t)(c.p - info->data);
            uint64_t code = rd_uleb(&c);
            if (code == 0) continue;
            const Abbrev *a = abbrev_of(&ab, code);
            if (a == NULL) break;
            const char *name = NULL, *linkage = NULL;
            uint64_t lo = 0, hi = 0, origin = 0;
            int has_lo = 0, has_hi = 0, hi_is_len = 0, has_origin = 0, has_ranges = 0;
            Val ranges = {V_NONE, 0, NULL, 0};
            Val strx_name = {V_NONE, 0, NULL, 0}, strx_linkage = {V_NONE, 0, NULL, 0};
            for (size_t i = 0; i < a->nattrs; i++) {
                Val v = read_form(x, &c, &u, a->attrs[i].form, a->attrs[i].implicit);
                switch (a->attrs[i].name) {
                case 0x03: if (v.kind == V_STRX) strx_name = v; else name = val_str(x, &u, &v); break;   // name
                case 0x6e: case 0x2007:                                                                  // linkage_name
                    if (v.kind == V_STRX) strx_linkage = v; else linkage = val_str(x, &u, &v);
                    break;
                case 0x11: if (val_addr(x, &u, &v, &lo)) has_lo = 1; break;                             // low_pc
                case 0x12:                                                                              // high_pc
                    if (v.form == 0x01 || v.kind == V_ADDRX) {
                        if (val_addr(x, &u, &v, &hi)) has_hi = 1;
                    } else if (v.kind == V_UINT) {
                        hi = v.u;
                        has_hi = 1;
                        hi_is_len = 1;
                    }
                    break;
                case 0x55: ranges = v; has_ranges = 1; break;                                           // ranges
                case 0x31: case 0x47: if (v.kind == V_REF) { origin = v.u; has_origin = 1; } break;    // abstract_origin, specification
                case 0x72: u.str_offsets_base = v.u; break;
                case 0x73: u.addr_base = v.u; break;
                case 0x74: u.rnglists_base = v.u; break;
                default: break;
                }
            }
            if (c.bad) break;
            if (strx_name.kind == V_STRX) name = val_str(x, &u, &strx_name);
            if (strx_linkage.kind == V_STRX) linkage = val_str(x, &u, &strx_linkage);
            if (hi_is_len) hi += lo;
            if (a->tag == 0x11) {                                // compile_unit
                u.base_pc = has_lo ? lo : 0;
                continue;
            }
            if (a->tag != 0x2e && a->tag != 0x1d) continue;     // subprogram, inlined_subroutine
            if (name != NULL || linkage != NULL) {
                if (ndn == capdn) {
                    capdn = capdn ? capdn * 2 : 4096;
                    dn = must_grow(dn, capdn * sizeof(DieName));
                }
                dn[ndn++] = (DieName){die_off, name, linkage};
            }
            if (linkage != NULL && name != NULL) {
                if (d->nnames == capnames) {
                    capnames = capnames ? capnames * 2 : 4096;
                    d->names = must_grow(d->names, capnames * sizeof(NamePair));
                }
                d->names[d->nnames++] = (NamePair){linkage, name};
            }
            if (!(has_lo && has_hi) && !has_ranges) continue;
            const char *fname = linkage != NULL ? linkage : name;
            if (fname == NULL && has_origin) {
                if (npend == cappend) {
                    cappend = cappend ? cappend * 2 : 4096;
                    pend = must_grow(pend, cappend * sizeof(Pending));
                }
                pend[npend++] = (Pending){lo, hi, has_lo && has_hi, origin, ranges, has_ranges, u};
                continue;
            }
            if (has_lo && has_hi) add_fn(d, lo, hi, fname);
            else add_ranges(x, d, &u, &ranges, fname);
        }
        for (size_t i = 0; i < ab.n; i++) free(ab.items[i].attrs);
        free(ab.items);
        off = next;
    }
    qsort(dn, ndn, sizeof *dn, compare_dienames);
    for (size_t i = 0; i < npend; i++) {
        const char *fname = NULL;
        uint64_t at = pend[i].origin;
        // An origin may itself name an origin: follow a few.
        for (int hop = 0; hop < 8 && fname == NULL; hop++) {
            const DieName *o = diename_at(dn, ndn, at);
            if (o == NULL) break;
            fname = o->linkage != NULL ? o->linkage : o->name;
        }
        if (fname == NULL) continue;
        if (pend[i].has_pc) add_fn(d, pend[i].lo, pend[i].hi, fname);
        else add_ranges(x, d, &pend[i].unit, &pend[i].ranges, fname);
    }
    free(pend);
    free(dn);
    qsort(d->names, d->nnames, sizeof *d->names, compare_names);
}

static void add_line(Debug *d, uint64_t lo, uint64_t hi, const char *file, uint64_t line) {
    if (hi <= lo) return;
    if (d->nlines == d->caplines) {
        d->caplines = d->caplines ? d->caplines * 2 : 4096;
        d->lines = must_grow(d->lines, d->caplines * sizeof(LineRange));
    }
    d->lines[d->nlines++] = (LineRange){lo, hi, file, line};
}

// A file's name as a line table gives it: its directory before it when the
// directory is not the unit's own (index 0 in DWARF 4, where it is implied).
static const char *join_path(const char *dir, const char *file) {
    if (dir == NULL || dir[0] == 0 || file[0] == '/' || strcmp(dir, ".") == 0) return file;
    size_t n = strlen(dir) + strlen(file) + 2;
    char *s = must_alloc(n);
    snprintf(s, n, "%s/%s", dir, file);
    return s;
}

// A v5 directory or file entry's path, by its format.
static const char *read_entry(const Exe *x, Cur *c, const Unit *u, const uint64_t *fmt, size_t nfmt, uint64_t *dir) {
    const char *path = "";
    *dir = 0;
    for (size_t i = 0; i < nfmt; i++) {
        Val v = read_form(x, c, u, fmt[2 * i + 1], 0);
        if (fmt[2 * i] == 1) {                          // DW_LNCT_path
            const char *s = val_str(x, u, &v);
            if (s != NULL) path = s;
        } else if (fmt[2 * i] == 2) {                   // DW_LNCT_directory_index
            *dir = v.u;
        }
    }
    return path;
}

static void read_lines(const Exe *x, Debug *d) {
    const Section *sec = &x->debug_line;
    if (sec->data == NULL) return;
    uint64_t off = 0;
    while (off + 4 <= sec->size) {
        Cur c = {sec->data + off, sec->data + sec->size, 0};
        Unit u;
        memset(&u, 0, sizeof u);
        u.offset_size = 4;
        uint64_t len = rd_n(&c, 4);
        if (len == 0xffffffff) {
            len = rd_n(&c, 8);
            u.offset_size = 8;
        }
        const uint8_t *end = c.p + len;
        if (end > c.end || len == 0) break;
        c.end = end;
        uint64_t next = (uint64_t)(end - sec->data);
        u.version = (int)rd_n(&c, 2);
        u.addr_size = 8;
        if (u.version >= 5) {
            u.addr_size = (int)rd_n(&c, 1);
            rd_n(&c, 1);                                // segment selector size
        }
        uint64_t header_len = rd_n(&c, u.offset_size);
        const uint8_t *program = c.p + header_len;
        int min_inst = (int)rd_n(&c, 1);
        int max_ops = 1;
        if (u.version >= 4) max_ops = (int)rd_n(&c, 1);
        (void)max_ops;
        int default_stmt = (int)rd_n(&c, 1);
        (void)default_stmt;
        int8_t line_base = (int8_t)rd_n(&c, 1);
        uint8_t line_range = (uint8_t)rd_n(&c, 1);
        uint8_t opcode_base = (uint8_t)rd_n(&c, 1);
        uint8_t std_len[256];
        memset(std_len, 0, sizeof std_len);
        for (int i = 1; i < opcode_base; i++) std_len[i] = (uint8_t)rd_n(&c, 1);
        const char **dirs = NULL, **files = NULL;
        size_t ndirs = 0, nfiles = 0;
        if (u.version >= 5) {
            uint64_t fmt[64];
            size_t nfmt = rd_n(&c, 1);
            if (nfmt > 32) break;
            for (size_t i = 0; i < 2 * nfmt; i++) fmt[i] = rd_uleb(&c);
            ndirs = rd_uleb(&c);
            if (ndirs > 1000000) break;
            dirs = must_alloc(ndirs * sizeof(char *));
            for (size_t i = 0; i < ndirs; i++) {
                uint64_t ignored;
                dirs[i] = read_entry(x, &c, &u, fmt, nfmt, &ignored);
            }
            nfmt = rd_n(&c, 1);
            if (nfmt > 32) break;
            for (size_t i = 0; i < 2 * nfmt; i++) fmt[i] = rd_uleb(&c);
            nfiles = rd_uleb(&c);
            if (nfiles > 1000000) break;
            files = must_alloc(nfiles * sizeof(char *));
            for (size_t i = 0; i < nfiles; i++) {
                uint64_t dir;
                const char *p = read_entry(x, &c, &u, fmt, nfmt, &dir);
                files[i] = join_path(dir > 0 && dir < ndirs ? dirs[dir] : NULL, p);
            }
        } else {
            size_t cap = 0;
            dirs = must_alloc(sizeof(char *));
            dirs[ndirs++] = NULL;                       // 0: the unit's own directory
            for (;;) {
                const char *s = rd_str(&c);
                if (s[0] == 0 || c.bad) break;
                dirs = must_grow(dirs, (ndirs + 1) * sizeof(char *));
                dirs[ndirs++] = s;
            }
            files = must_alloc(sizeof(char *));
            files[nfiles++] = "?";                      // DWARF 4 numbers files from 1
            for (;;) {
                const char *s = rd_str(&c);
                if (s[0] == 0 || c.bad) break;
                uint64_t dir = rd_uleb(&c);
                rd_uleb(&c);
                rd_uleb(&c);
                if (nfiles + 1 > cap) {
                    cap = cap ? cap * 2 : 16;
                    files = must_grow(files, (cap + 1) * sizeof(char *));
                }
                files[nfiles++] = join_path(dir < ndirs ? dirs[dir] : NULL, s);
            }
        }
        if (c.bad) break;
        c.p = program;
        // The state machine: each row covers from its address to the next
        // row's, within a sequence.
        uint64_t addr = 0, file = 1, line = 1;
        int have_row = 0;
        uint64_t row_addr = 0, row_file = 0, row_line = 0;
        while (c.p < c.end && !c.bad) {
            uint8_t op = (uint8_t)rd_n(&c, 1);
            int emit = 0, end_seq = 0;
            if (op >= opcode_base) {
                int adj = op - opcode_base;
                addr += (uint64_t)(adj / line_range) * (uint64_t)min_inst;
                line += (uint64_t)(int64_t)(line_base + adj % line_range);
                emit = 1;
            } else if (op == 0) {
                uint64_t n = rd_uleb(&c);
                const uint8_t *after = c.p + n;
                uint8_t ext = (uint8_t)rd_n(&c, 1);
                if (ext == 1) {
                    emit = 1;
                    end_seq = 1;
                } else if (ext == 2) {
                    addr = rd_n(&c, (int)(n - 1));
                }
                c.p = after;
            } else {
                switch (op) {
                case 1: emit = 1; break;                                     // copy
                case 2: addr += rd_uleb(&c) * (uint64_t)min_inst; break;    // advance_pc
                case 3: line += (uint64_t)rd_sleb(&c); break;               // advance_line
                case 4: file = rd_uleb(&c); break;                          // set_file
                case 5: rd_uleb(&c); break;                                 // set_column
                case 6: case 7: case 10: case 11: break;
                case 8: addr += (uint64_t)((255 - opcode_base) / line_range) * (uint64_t)min_inst; break;
                case 9: addr += rd_n(&c, 2); break;                         // fixed_advance_pc
                case 12: rd_uleb(&c); break;                                // set_isa
                default:
                    for (int i = 0; i < std_len[op]; i++) rd_uleb(&c);
                }
            }
            if (!emit) continue;
            if (have_row) {
                const char *fname = row_file < nfiles ? files[row_file] : "?";
                add_line(d, row_addr, addr, fname, row_line);
            }
            if (end_seq) {
                have_row = 0;
                addr = 0;
                file = 1;
                line = 1;
            } else {
                have_row = 1;
                row_addr = addr;
                row_file = file;
                row_line = line;
            }
        }
        off = next;
    }
}

static int compare_lines(const void *a, const void *b) {
    const LineRange *x = a, *y = b;
    return x->lo < y->lo ? -1 : x->lo > y->lo;
}

static Debug *debug_read(const Exe *x) {
    Debug *d = must_alloc(sizeof *d);
    read_info(x, d);
    read_lines(x, d);
    qsort(d->lines, d->nlines, sizeof *d->lines, compare_lines);
    return d;
}

static const char *roc_name(const Debug *d, const char *symbol) {
    size_t lo = 0, hi = d->nnames;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int k = strcmp(d->names[mid].symbol, symbol);
        if (k == 0) return d->names[mid].name;
        if (k < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

// The file and line an address is at, NULL for none: the row of the line
// table that covers it (the last such row, as rows overlap only where a
// table repeats an address).
static const LineRange *line_at(const Debug *d, uint64_t a) {
    size_t lo = 0, hi = d->nlines;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (d->lines[mid].lo <= a) lo = mid + 1;
        else hi = mid;
    }
    // Rows that start at or below `a`, the latest first; a few steps back
    // covers sequences that overlap.
    for (size_t k = lo, tries = 0; k > 0 && tries < 64; k--, tries++) {
        const LineRange *r = &d->lines[k - 1];
        if (a >= r->lo && a < r->hi) return r;
    }
    return NULL;
}

// The innermost function DWARF says covers an address, by its linkage name
// (or plain name when it has none).
static const char *fn_at(const Debug *d, uint64_t a) {
    const FnRange *best = NULL;
    for (size_t i = 0; i < d->nfns; i++) {
        const FnRange *f = &d->fns[i];
        if (a >= f->lo && a < f->hi && (best == NULL || f->hi - f->lo < best->hi - best->lo)) best = f;
    }
    return best ? best->name : NULL;
}

// ─── Running a program under ptrace ──────────────────────────────────────

enum { ID_ALLOC = -1, ID_REALLOC = -2, ID_DEALLOC = -3 };
enum { CHAIN = 6, TABLE = 1 << 16 };
enum { W_ENTRY = 0, W_VIA = 1, W_DIRECT = 2 };
enum { KIND_ALLOC = 0, KIND_REALLOC = 1 };

typedef struct {
    uint64_t at;        // an offset in the file's addresses
    int id;             // a builtin's index; ID_ALLOC and the rest for the allocator
} Point;

typedef struct {
    uint64_t start, end;
    const char *name;
} Proc;

typedef struct {
    uint64_t at[CHAIN];
} Sites;

typedef struct {
    int used, what, kind, id;
    Sites sites;
    uint64_t count, bytes;
} Slot;

// What the breakpoints are for: the allocator alone (`count`), or the
// builtins and the Roc procedures too (`where`).
typedef struct {
    Exe *exe;
    Point *points;
    size_t npoints;
    Proc *procs;        // sorted by start
    size_t nprocs;
    const char **entry_names;
    size_t nentries;
    int where;
    Debug *debug;
} Plan;

typedef struct {
    uint64_t alloc, realloc, dealloc;
    Slot *table;        // `where` only
    char *output;       // the last bytes the program printed
    size_t output_size;
    char *output_path;
} RunResult;

static void plan_add_point(Plan *p, uint64_t at, int id) {
    for (size_t i = 0; i < p->npoints; i++) {
        if (p->points[i].at == at) return;   // one breakpoint an address
    }
    p->points = must_grow(p->points, (p->npoints + 1) * sizeof(Point));
    p->points[p->npoints++] = (Point){at, id};
}

static uint64_t allocator_at(const Exe *x, const char *name) {
    const Sym *s = sym_named(x, name);
    if (s == NULL)
        fail("%s has no %s in its symbol table: is it a Roc program on a platform that allocates through it?", x->path, name);
    return s->value;
}

// A builtin's short name: `list_set` for `dev_wrappers.roc_builtins_list_set`.
static const char *short_name(const char *name) {
    const char *p = name;
    while ((p = strstr(p, "roc_builtins_")) != NULL) {
        const char *rest = p + strlen("roc_builtins_");
        const char *q = rest;
        while ((*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9') || *q == '_') q++;
        if (*q == 0 && q > rest) return rest;
        p++;
    }
    return name;
}

// Whether a function is builtin code to break at the entry of: a named
// builtin, its wrappers and shims, or a list helper, but none of the
// refcounting ones, which run everywhere.
static int is_entry(const char *name) {
    if (strstr(name, "incref") || strstr(name, "decref") || strstr(name, "free")) return 0;
    if (strstr(name, "drop") && !strstr(name, "drop_at")) return 0;
    if (strcmp(name, "roc_desc_list_op") == 0) return 1;
    return starts_with(name, "roc_builtins_") || starts_with(name, "dev_wrappers.roc_builtins_") ||
           starts_with(name, "roc_cold_shim.roc_builtins_") || starts_with(name, "list.") || starts_with(name, "str.");
}

// The builtins whose allocation is a copy of what they write into: RC1's
// uniqueness-checked ops, by the names the builtins keep in every build,
// and the dev build's `roc_desc_list_op`, the generic list op it runs for a
// list whose entries hold a reference count (a `List(Str)`).
static const char *const WRITERS[] = {"list_set", "list_replace", "list_swap", "list_concat", "list_prepend",
    "list_reserve", "list_reserve_for_append", "list_drop_at", "list_reverse", "list_append_unsafe",
    "list_append_sublist", "list_append_range_within", "list_append_le_bytes", "list_copy_range_within",
    "list_clear", "list_map_can_reuse", "list_owned_unique", "str_concat", "str_trim", "str_trim_start",
    "str_trim_end", "str_with_ascii_lowercased", "str_with_ascii_uppercased", "str_reserve", "roc_desc_list_op"};

static int is_writer(const char *builtin) {
    for (size_t i = 0; i < sizeof WRITERS / sizeof WRITERS[0]; i++) {
        if (strcmp(WRITERS[i], builtin) == 0) return 1;
    }
    return 0;
}

static int compare_procs(const void *a, const void *b) {
    const Proc *x = a, *y = b;
    return x->start < y->start ? -1 : x->start > y->start;
}

static Plan *plan_for(const char *path, int where) {
    Plan *p = must_alloc(sizeof *p);
    p->exe = exe_open(path);
    p->where = where;
    Exe *x = p->exe;
    plan_add_point(p, allocator_at(x, "roc_alloc"), ID_ALLOC);
    // A program that never grows or frees in place may have neither of
    // these: the linker drops a function nothing calls, and its count is 0.
    const Sym *re = sym_named(x, "roc_realloc");
    if (re != NULL) plan_add_point(p, re->value, ID_REALLOC);
    const Sym *de = sym_named(x, "roc_dealloc");
    if (!where) {
        if (de != NULL) plan_add_point(p, de->value, ID_DEALLOC);
        return p;
    }
    p->procs = must_alloc(x->nsyms * sizeof(Proc));
    p->entry_names = must_alloc(x->nsyms * sizeof(char *));
    for (size_t i = 0; i < x->nsyms; i++) {
        const Sym *s = &x->syms[i];
        if (s->size == 0) continue;
        if (strcmp(s->name, "roc_alloc") == 0 || strcmp(s->name, "roc_realloc") == 0) continue;
        if (starts_with(s->name, "roc__p")) {
            p->procs[p->nprocs++] = (Proc){s->value, s->value + s->size, s->name};
        } else if (is_entry(s->name)) {
            size_t before = p->npoints;
            plan_add_point(p, s->value, (int)p->nentries);
            if (p->npoints > before) p->entry_names[p->nentries++] = s->name;
        }
    }
    if (p->nprocs == 0) fail("%s names no Roc procedure (no roc__p symbol)", path);
    qsort(p->procs, p->nprocs, sizeof *p->procs, compare_procs);
    p->debug = debug_read(x);
    return p;
}

static const Proc *proc_at(const Plan *p, uint64_t offset) {
    size_t lo = 0, hi = p->nprocs;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (offset < p->procs[mid].start) hi = mid;
        else if (offset >= p->procs[mid].end) lo = mid + 1;
        else return &p->procs[mid];
    }
    return NULL;
}

static volatile sig_atomic_t timed_out = 0;

static void on_alarm(int sig) {
    (void)sig;
    timed_out = 1;
}

typedef struct {
    pid_t pid;
    const char *what;   // the run's name, for messages
    pid_t born;         // a thread or process it started, which is refused
} Tracee;

// The thread or process a clone or fork event stop names.
static void note_born(Tracee *t) {
    unsigned long born = 0;
    if (ptrace(PTRACE_GETEVENTMSG, t->pid, NULL, &born) == 0) t->born = (pid_t)born;
}

static void stop_tracee(Tracee *t) {
    // A process or thread the program just started is attached and stopped
    // too: it goes with it, or the wait below would wait on it for good.
    if (t->born > 0) kill(t->born, SIGKILL);
    kill(t->pid, SIGKILL);
    alarm(0);
    int status;
    while (waitpid(-1, &status, __WALL) > 0) {}
}

static void tracee_fail(Tracee *t, const char *fmt, ...) {
    int e = errno;
    stop_tracee(t);
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, TOOL ": %s: ", t->what);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (e != 0) fprintf(stderr, " (%s)", strerror(e));
    fprintf(stderr, "\n");
    exit(EXIT_FAIL);
}

static uint64_t peek(Tracee *t, uint64_t at) {
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, t->pid, (void *)at, NULL);
    if (errno != 0) tracee_fail(t, "could not read the program's memory at %#" PRIx64, at);
    return (uint64_t)w;
}

static void poke(Tracee *t, uint64_t at, uint64_t w) {
    if (ptrace(PTRACE_POKEDATA, t->pid, (void *)at, (void *)w) != 0)
        tracee_fail(t, "could not write the program's code at %#" PRIx64, at);
}

static uint64_t with_trap(uint64_t w) {
    return (w & ~(uint64_t)0xff) | 0xcc;
}

// Where the kernel loaded the executable: AT_ENTRY, the entry point it
// mapped, less the entry point the file names. This reads the kernel's own
// answer; picking the first mapping at file offset 0 instead finds [vvar]
// whenever the kernel puts the vDSO below a static PIE.
static uint64_t load_base(Tracee *t, const Exe *x) {
    if (x->eh->e_type == ET_EXEC) return 0;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/auxv", (int)t->pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) tracee_fail(t, "could not open %s", path);
    uint64_t pair[2];
    uint64_t entry = 0;
    while (read(fd, pair, sizeof pair) == (ssize_t)sizeof pair) {
        if (pair[0] == AT_NULL) break;
        if (pair[0] == AT_ENTRY) entry = pair[1];
    }
    close(fd);
    errno = 0;
    if (entry == 0) tracee_fail(t, "the kernel gave no entry point (AT_ENTRY)");
    return entry - x->eh->e_entry;
}

// Each counted call stops the program: a call's stop, the breakpoint taken
// out, one instruction stepped, the breakpoint put back.
typedef struct {
    uint64_t at;        // the address in the running program
    uint64_t saved;     // the word there before the int3
    int id;
} Armed;

static uint64_t hash_sites(int what, int kind, int id, const Sites *s) {
    uint64_t h = ((uint64_t)(id + 7) << 40) ^ ((uint64_t)what << 56) ^ ((uint64_t)kind << 60);
    for (int i = 0; i < CHAIN; i++) h = (h ^ s->at[i]) * 0x9e3779b97f4a7c15ULL;
    return h;
}

static void tally(Tracee *t, Slot *table, int what, int kind, int id, const Sites *sites, uint64_t bytes) {
    uint64_t h = hash_sites(what, kind, id, sites);
    for (uint64_t probe = 0; probe < TABLE; probe++) {
        Slot *s = &table[(h + probe) & (TABLE - 1)];
        if (!s->used) {
            *s = (Slot){1, what, kind, id, *sites, 1, bytes};
            return;
        }
        if (s->what == what && s->kind == kind && s->id == id && memcmp(&s->sites, sites, sizeof *sites) == 0) {
            s->count++;
            s->bytes += bytes;
            return;
        }
    }
    errno = 0;
    tracee_fail(t, "more call sites than the table holds (%d)", TABLE);
}

// At a function's first instruction: its return address, then those the
// frame pointers lead to, each as an offset in the file's addresses. A
// frame pointer that is not above the last, not 8-aligned, or not within
// 64 MiB of the stack's top ends the walk: code built without frame
// pointers leaves `rbp` as anything.
static Sites sites_at(Tracee *t, const struct user_regs_struct *r, uint64_t base) {
    Sites s;
    memset(&s, 0, sizeof s);
    s.at[0] = peek(t, r->rsp) - base;
    uint64_t frame = r->rbp, floor = r->rsp;
    for (int i = 1; i < CHAIN; i++) {
        if (frame <= floor || frame - r->rsp > ((uint64_t)64 << 20) || (frame & 7) != 0) break;
        uint64_t back = peek(t, frame + 8);
        if (back < base) break;
        s.at[i] = back - base;
        floor = frame;
        frame = peek(t, frame);
    }
    return s;
}

static int event_of(int status) {
    return status >> 16;
}

static const char *thread_refusal =
    "the program started a thread (clone); " TOOL " traces single-threaded programs only, "
    "since a thread it did not trace would stop for good at its first breakpoint";

// Runs `argv` under the breakpoints of `plan`, its output kept in a file,
// and gives what it counted. `timeout_s` 0 is no limit.
static RunResult trace_run(const Plan *plan, char *const *argv, const char *what, unsigned timeout_s) {
    RunResult res;
    memset(&res, 0, sizeof res);
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == 0) tmp = "/tmp";
    size_t n = strlen(tmp) + 40;
    res.output_path = must_alloc(n);
    snprintf(res.output_path, n, "%s/roc-alloc-trace-out.XXXXXX", tmp);
    int out_fd = mkstemp(res.output_path);
    if (out_fd < 0) fail("could not make a file in %s for the program's output: %s", tmp, strerror(errno));
    fflush(NULL);
    Tracee t = {fork(), what, 0};
    if (t.pid < 0) fail("fork: %s", strerror(errno));
    if (t.pid == 0) {
        int in = open("/dev/null", O_RDONLY);
        if (in >= 0) dup2(in, 0);
        dup2(out_fd, 1);
        dup2(out_fd, 2);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            fprintf(stderr, TOOL ": could not trace the program: %s\n", strerror(errno));
            _exit(127);
        }
        if (strchr(argv[0], '/') != NULL) execv(argv[0], argv);
        else execvp(argv[0], argv);
        fprintf(stderr, TOOL ": could not start %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(out_fd);
    int status = 0;
    if (waitpid(t.pid, &status, 0) != t.pid) tracee_fail(&t, "could not wait for the program's start");
    if (!WIFSTOPPED(status)) {
        errno = 0;
        tracee_fail(&t, "the program did not start (see its output in %s)", res.output_path);
    }
    long opts = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, t.pid, NULL, (void *)opts) != 0) tracee_fail(&t, "could not set the trace's options");
    uint64_t base = load_base(&t, plan->exe);
    Armed *armed = must_alloc(plan->npoints * sizeof(Armed));
    for (size_t i = 0; i < plan->npoints; i++) {
        uint64_t at = base + plan->points[i].at;
        uint64_t word = peek(&t, at);
        // The load base is right only if the code there is the file's: a
        // wrong base is a loud stop, never a quiet count of nothing.
        uint8_t want[8];
        size_t have = file_bytes_at(plan->exe, plan->points[i].at, want, 8);
        if (have == 0 || memcmp(&word, want, have) != 0) {
            errno = 0;
            tracee_fail(&t, "the code at %#" PRIx64 " is not the file's: the load base %#" PRIx64 " is wrong",
                plan->points[i].at, base);
        }
        armed[i] = (Armed){at, word, plan->points[i].id};
        poke(&t, at, with_trap(word));
    }
    if (plan->where) res.table = must_alloc(TABLE * sizeof(Slot));
    int last_id = -1;
    Sites last_sites;
    memset(&last_sites, 0, sizeof last_sites);
    timed_out = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);   // no SA_RESTART: a wait ends on the alarm
    alarm(timeout_s);
    int pass = 0;
    for (;;) {
        if (ptrace(PTRACE_CONT, t.pid, NULL, (void *)(intptr_t)pass) != 0) tracee_fail(&t, "could not continue the program");
        pass = 0;
        if (waitpid(t.pid, &status, 0) != t.pid) {
            if (errno == EINTR && timed_out) {
                errno = 0;
                tracee_fail(&t, "the program ran past the limit of %u s", timeout_s);
            }
            tracee_fail(&t, "could not wait for the program");
        }
        if (timed_out) {
            errno = 0;
            tracee_fail(&t, "the program ran past the limit of %u s", timeout_s);
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        int ev = event_of(status);
        if (ev == PTRACE_EVENT_CLONE) {
            note_born(&t);
            errno = 0;
            tracee_fail(&t, "%s", thread_refusal);
        }
        if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK) {
            note_born(&t);
            errno = 0;
            tracee_fail(&t, "the program started a process (fork); " TOOL " traces one process, whose breakpoints a child would inherit untraced");
        }
        if (ev == PTRACE_EVENT_EXEC) {
            errno = 0;
            tracee_fail(&t, "the program ran another program (exec), which has none of the breakpoints");
        }
        if (sig != SIGTRAP) {
            pass = sig;
            continue;
        }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, t.pid, NULL, &regs) != 0) tracee_fail(&t, "could not read the program's registers");
        int which = -1;
        for (size_t i = 0; i < plan->npoints; i++) {
            if (regs.rip - 1 == armed[i].at) which = (int)i;
        }
        if (which < 0) {
            pass = SIGTRAP;   // the program's own trap, not one of ours
            continue;
        }
        int id = armed[which].id;
        if (id == ID_ALLOC) res.alloc++;
        else if (id == ID_REALLOC) res.realloc++;
        else if (id == ID_DEALLOC) res.dealloc++;
        if (plan->where) {
            // At a function's first instruction the return address is on
            // top of the stack.
            uint64_t back = peek(&t, regs.rsp) - base;
            if (id >= 0) {
                if (proc_at(plan, back) != NULL) {
                    last_id = id;
                    last_sites = sites_at(&t, &regs, base);
                    tally(&t, res.table, W_ENTRY, 0, id, &last_sites, 0);
                }
            } else {
                int kind = id == ID_ALLOC ? KIND_ALLOC : KIND_REALLOC;
                // roc_alloc(size, alignment); roc_realloc(ptr, new, old, alignment).
                uint64_t bytes = kind == KIND_ALLOC ? regs.rdi : regs.rsi;
                if (proc_at(plan, back) != NULL) {
                    Sites here = sites_at(&t, &regs, base);
                    tally(&t, res.table, W_DIRECT, kind, -1, &here, bytes);
                } else {
                    tally(&t, res.table, W_VIA, kind, last_id, &last_sites, bytes);
                }
            }
        }
        // The call's first instruction put back and run alone, then the
        // breakpoint set again. A signal that arrives before the step is
        // taken is held and delivered at the next continue, and the step
        // tried again, so no call is counted twice.
        poke(&t, armed[which].at, armed[which].saved);
        regs.rip -= 1;
        if (ptrace(PTRACE_SETREGS, t.pid, NULL, &regs) != 0) tracee_fail(&t, "could not write the program's registers");
        int stepped = 0;
        while (!stepped) {
            if (ptrace(PTRACE_SINGLESTEP, t.pid, NULL, NULL) != 0) tracee_fail(&t, "could not step the program");
            if (waitpid(t.pid, &status, 0) != t.pid) {
                if (errno == EINTR && timed_out) {
                    errno = 0;
                    tracee_fail(&t, "the program ran past the limit of %u s", timeout_s);
                }
                tracee_fail(&t, "could not wait for the program's step");
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && event_of(status) == 0) stepped = 1;
            else if (WIFSTOPPED(status) && event_of(status) != 0) {
                note_born(&t);
                errno = 0;
                tracee_fail(&t, "%s", thread_refusal);
            } else if (WIFSTOPPED(status) && event_of(status) == 0) pass = WSTOPSIG(status);
        }
        if (!stepped) break;
        poke(&t, armed[which].at, with_trap(armed[which].saved));
    }
    alarm(0);
    free(armed);
    // The last 64 KiB of what it printed, for messages and checks.
    FILE *f = fopen(res.output_path, "r");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        long from = size > 65536 ? size - 65536 : 0;
        fseek(f, from, SEEK_SET);
        res.output = must_alloc((size_t)(size - from) + 1);
        res.output_size = fread(res.output, 1, (size_t)(size - from), f);
        res.output[res.output_size] = 0;
        fclose(f);
    } else {
        res.output = must_dup("");
    }
    unlink(res.output_path);
    if (WIFSIGNALED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, TOOL ": %s: the program ", what);
        if (WIFSIGNALED(status)) fprintf(stderr, "died of signal %d", WTERMSIG(status));
        else fprintf(stderr, "exited %d", WEXITSTATUS(status));
        fprintf(stderr, "; the end of its output:\n");
        size_t at = res.output_size > 2000 ? res.output_size - 2000 : 0;
        fprintf(stderr, "%s\n", res.output + at);
        exit(EXIT_FAIL);
    }
    return res;
}

static void result_free(RunResult *r) {
    free(r->table);
    free(r->output);
    free(r->output_path);
}

// ─── Controls: what to run, at which sizes ───────────────────────────────

enum { SHAPE_TEMPLATE, SHAPE_PAIR, SHAPE_ONCE };

typedef struct {
    char **v;
    int n;
} Argv;

typedef struct {
    char *name;
    int line;                // in the check file
    int held;                // whether the counts below are held
    int64_t alloc_h, realloc_h;   // hundredths an iteration (a `once` control: the total)
    char *why;
    int shape;
    Argv run, small, big;
} Control;

typedef struct {
    const char *path;
    long small, big;
    int64_t slack_h;
    unsigned timeout_s;
    char **refuse_words;
    int nrefuse;
    Control *controls;
    int ncontrols;
} CheckFile;

static void argv_push(Argv *a, char *s) {
    a->v = must_grow(a->v, (size_t)(a->n + 2) * sizeof(char *));
    a->v[a->n++] = s;
    a->v[a->n] = NULL;
}

static int has_n(const Argv *a) {
    for (int i = 0; i < a->n; i++) {
        if (strstr(a->v[i], "{N}") != NULL) return 1;
    }
    return 0;
}

// `a` with every `{N}` replaced by `n`.
static Argv argv_at(const Argv *a, long n) {
    Argv out = {NULL, 0};
    char num[32];
    snprintf(num, sizeof num, "%ld", n);
    for (int i = 0; i < a->n; i++) {
        const char *s = a->v[i];
        size_t cap = strlen(s) + 1, len = 0;
        char *r = must_alloc(cap);
        while (*s) {
            if (strncmp(s, "{N}", 3) == 0) {
                cap += strlen(num);
                r = must_grow(r, cap);
                memcpy(r + len, num, strlen(num));
                len += strlen(num);
                s += 3;
            } else {
                r[len++] = *s++;
            }
        }
        r[len] = 0;
        argv_push(&out, r);
    }
    return out;
}

// A count an iteration as a check file writes it, `2` or `2.03`, in
// hundredths; -1 for anything else.
static int64_t parse_hundredths(const char *s) {
    int64_t whole = 0;
    const char *p = s;
    if (!(*p >= '0' && *p <= '9')) return -1;
    while (*p >= '0' && *p <= '9') whole = whole * 10 + (*p++ - '0');
    int64_t frac = 0;
    if (*p == '.') {
        p++;
        if (!(p[0] >= '0' && p[0] <= '9' && p[1] >= '0' && p[1] <= '9')) return -1;
        frac = (p[0] - '0') * 10 + (p[1] - '0');
        p += 2;
    }
    if (*p != 0) return -1;
    return whole * 100 + frac;
}

static void hundredths_str(int64_t h, char *out, size_t n) {
    const char *sign = h < 0 ? "-" : "";
    int64_t a = h < 0 ? -h : h;
    snprintf(out, n, "%s%" PRId64 ".%02" PRId64, sign, a / 100, a % 100);
}

// What a count grew by an iteration, in hundredths, truncated toward zero.
static int64_t per_iteration(uint64_t small, uint64_t big, long iterations) {
    int64_t diff = ((int64_t)big - (int64_t)small) * 100;
    if (diff < 0) return -((-diff) / iterations);
    return diff / iterations;
}

static void file_fail(const CheckFile *f, int line, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, TOOL ": %s:%d: ", f->path, line);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(EXIT_FAIL);
}

// The words of a line, as a shell splits them: spaces apart, '...' taken
// as written, "..." with \n, \t, \\, \" and \xHH.
static Argv split_words(const CheckFile *f, int lineno, const char *s) {
    Argv a = {NULL, 0};
    const char *p = s;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '\n') break;
        size_t cap = strlen(p) + 1, len = 0;
        char *w = must_alloc(cap);
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            if (*p == '\'') {
                p++;
                while (*p && *p != '\'') w[len++] = *p++;
                if (*p != '\'') file_fail(f, lineno, "a ' is not closed");
                p++;
            } else if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\') {
                        p++;
                        switch (*p) {
                        case 'n': w[len++] = '\n'; p++; break;
                        case 't': w[len++] = '\t'; p++; break;
                        case '\\': w[len++] = '\\'; p++; break;
                        case '"': w[len++] = '"'; p++; break;
                        case 'x': {
                            int v = 0;
                            for (int k = 1; k <= 2; k++) {
                                char ch = p[k];
                                int d = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
                                      : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
                                if (d < 0) file_fail(f, lineno, "\\x takes two hex digits");
                                v = v * 16 + d;
                            }
                            w[len++] = (char)v;
                            p += 3;
                            break;
                        }
                        default: file_fail(f, lineno, "\\%c is no escape this file reads (\\n \\t \\\\ \\\" \\xHH)", *p);
                        }
                    } else {
                        w[len++] = *p++;
                    }
                }
                if (*p != '"') file_fail(f, lineno, "a \" is not closed");
                p++;
            } else {
                w[len++] = *p++;
            }
        }
        w[len] = 0;
        argv_push(&a, w);
    }
    return a;
}

static Argv argv_rest(const Argv *a, int from) {
    Argv out = {NULL, 0};
    for (int i = from; i < a->n; i++) argv_push(&out, a->v[i]);
    return out;
}

static long parse_count(const CheckFile *f, int line, const char *what, const char *s) {
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != 0 || v < 0) file_fail(f, line, "%s takes a whole number, not %s", what, s);
    return v;
}

static CheckFile read_check_file(const char *path) {
    CheckFile f;
    memset(&f, 0, sizeof f);
    f.path = path;
    f.small = 1000;
    f.big = 10000;
    f.slack_h = 5;
    f.timeout_s = 600;
    FILE *in = fopen(path, "r");
    if (in == NULL) fail("%s: %s", path, strerror(errno));
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0;
    Control *cur = NULL;
    while (getline(&line, &cap, in) >= 0) {
        lineno++;
        const char *p = line;
        int indented = *p == ' ' || *p == '\t';
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '\n' || *p == '#') continue;
        Argv w;
        if (indented) {
            w = split_words(&f, lineno, p);
        } else {
            // A setting's words, or a control's name and counts: plain
            // words, with a control's why after them taken as written.
            w = (Argv){NULL, 0};
            const char *q = p;
            for (int n = 0; *q && *q != '\n' && n < 64; n++) {
                const char *s = q;
                while (*q && *q != ' ' && *q != '\t' && *q != '\n') q++;
                char *word = must_alloc((size_t)(q - s) + 1);
                memcpy(word, s, (size_t)(q - s));
                argv_push(&w, word);
                while (*q == ' ' || *q == '\t') q++;
            }
        }
        const char *k = w.v[0];
        if (indented) {
            if (cur == NULL) file_fail(&f, lineno, "an indented line belongs under a control");
            if (w.n < 2) file_fail(&f, lineno, "`%s` takes a command line", k);
            Argv rest = argv_rest(&w, 1);
            if (strcmp(k, "run") == 0) {
                if (cur->run.n || cur->small.n || cur->big.n) file_fail(&f, lineno, "%s has its command line already", cur->name);
                if (!has_n(&rest)) file_fail(&f, lineno, "`run` has no {N}; a command line without a loop is `once`");
                cur->shape = SHAPE_TEMPLATE;
                cur->run = rest;
            } else if (strcmp(k, "once") == 0) {
                if (cur->run.n || cur->small.n || cur->big.n) file_fail(&f, lineno, "%s has its command line already", cur->name);
                cur->shape = SHAPE_ONCE;
                cur->run = rest;
            } else if (strcmp(k, "small") == 0 || strcmp(k, "big") == 0) {
                if (cur->run.n) file_fail(&f, lineno, "%s has a `run` or `once` line already", cur->name);
                Argv *slot = k[0] == 's' ? &cur->small : &cur->big;
                if (slot->n) file_fail(&f, lineno, "%s has its `%s` line already", cur->name, k);
                cur->shape = SHAPE_PAIR;
                *slot = rest;
            } else {
                file_fail(&f, lineno, "an indented line is `run`, `once`, `small` or `big`, not `%s`", k);
            }
            continue;
        }
        cur = NULL;
        if (strcmp(k, "small") == 0 || strcmp(k, "big") == 0 || strcmp(k, "timeout") == 0) {
            if (w.n != 2) file_fail(&f, lineno, "`%s` takes one number", k);
            long v = parse_count(&f, lineno, k, w.v[1]);
            if (k[0] == 's') f.small = v;
            else if (k[0] == 'b') f.big = v;
            else f.timeout_s = (unsigned)v;
        } else if (strcmp(k, "slack") == 0) {
            if (w.n != 2 || (f.slack_h = parse_hundredths(w.v[1])) < 0) file_fail(&f, lineno, "`slack` takes a count like 0.05");
        } else if (strcmp(k, "fail-if-printed") == 0) {
            for (int i = 1; i < w.n; i++) {
                f.refuse_words = must_grow(f.refuse_words, (size_t)(f.nrefuse + 1) * sizeof(char *));
                f.refuse_words[f.nrefuse++] = w.v[i];
            }
        } else {
            // A control: `<name> <allocs> <reallocs> [why...]`.
            if (w.n < 3) file_fail(&f, lineno, "a control is `<name> <allocs> <reallocs> [why]`, its command line indented below");
            for (int i = 0; i < f.ncontrols; i++) {
                if (strcmp(f.controls[i].name, k) == 0) file_fail(&f, lineno, "%s is named twice", k);
            }
            f.controls = must_grow(f.controls, (size_t)(f.ncontrols + 1) * sizeof(Control));
            cur = &f.controls[f.ncontrols++];
            memset(cur, 0, sizeof *cur);
            cur->name = w.v[0];
            cur->line = lineno;
            if (strcmp(w.v[1], "-") == 0 && strcmp(w.v[2], "-") == 0) {
                cur->held = 0;
            } else {
                cur->held = 1;
                cur->alloc_h = parse_hundredths(w.v[1]);
                cur->realloc_h = parse_hundredths(w.v[2]);
                if (cur->alloc_h < 0 || cur->realloc_h < 0)
                    file_fail(&f, lineno, "%s's counts are like 2 or 2.03 (or `- -` for a control held to nothing)", k);
            }
            // The why, as written after the two counts.
            const char *q = p;
            for (int i = 0; i < 3; i++) {
                while (*q && *q != ' ' && *q != '\t') q++;
                while (*q == ' ' || *q == '\t') q++;
            }
            cur->why = must_dup(q);
            size_t len = strlen(cur->why);
            while (len > 0 && (cur->why[len - 1] == '\n' || cur->why[len - 1] == ' ')) cur->why[--len] = 0;
        }
    }
    free(line);
    fclose(in);
    for (int i = 0; i < f.ncontrols; i++) {
        Control *c = &f.controls[i];
        if (c->shape == SHAPE_PAIR && (c->small.n == 0 || c->big.n == 0))
            file_fail(&f, c->line, "%s has a `small` line and no `big`, or the other way round", c->name);
        if (c->run.n == 0 && c->small.n == 0) file_fail(&f, c->line, "%s has no command line below it", c->name);
        if (c->shape == SHAPE_ONCE && c->held && (c->alloc_h % 100 != 0 || c->realloc_h % 100 != 0))
            file_fail(&f, c->line, "%s runs once, so its counts are whole numbers", c->name);
    }
    if (f.big <= f.small) file_fail(&f, 0, "big (%ld) must be more than small (%ld)", f.big, f.small);
    if (f.ncontrols == 0) file_fail(&f, lineno, "names no control");
    return f;
}

static Argv argv_for(const Control *c, int big, long small_n, long big_n) {
    if (c->shape == SHAPE_TEMPLATE) return argv_at(&c->run, big ? big_n : small_n);
    if (c->shape == SHAPE_PAIR) return big ? c->big : c->small;
    return c->run;
}

// ─── Mode `count` and mode `check` ───────────────────────────────────────

// One control measured: its counts at each size, and an iteration's.
typedef struct {
    RunResult small, big;
    int once;
    int64_t alloc_h, realloc_h, dealloc_h;
} Measured;

static Plan *cached_plan(const char *path, int where) {
    static Plan *last = NULL;
    if (last != NULL && last->where == where && strcmp(last->exe->path, path) == 0) return last;
    last = plan_for(path, where);
    return last;
}

static void check_output(const CheckFile *f, const Control *c, const RunResult *r) {
    for (int i = 0; i < f->nrefuse; i++) {
        if (strstr(r->output, f->refuse_words[i]) != NULL) {
            size_t at = r->output_size > 400 ? r->output_size - 400 : 0;
            fprintf(stderr, TOOL ": %s: the program printed `%s` (fail-if-printed); the end of its output:\n%s\n", c->name,
                f->refuse_words[i], r->output + at);
            exit(EXIT_FAIL);
        }
    }
}

static Measured measure(const CheckFile *f, const Control *c, int where) {
    Measured m;
    memset(&m, 0, sizeof m);
    Argv a = argv_for(c, 0, f->small, f->big);
    Plan *plan = cached_plan(a.v[0], where);
    char what[512];
    snprintf(what, sizeof what, "%s at %ld", c->name, f->small);
    if (c->shape == SHAPE_ONCE) {
        snprintf(what, sizeof what, "%s", c->name);
        m.once = 1;
        m.small = trace_run(plan, a.v, what, f->timeout_s);
        check_output(f, c, &m.small);
        return m;
    }
    m.small = trace_run(plan, a.v, what, f->timeout_s);
    check_output(f, c, &m.small);
    Argv b = argv_for(c, 1, f->small, f->big);
    if (strcmp(b.v[0], a.v[0]) != 0) fail("%s: its two command lines run two programs, %s and %s", c->name, a.v[0], b.v[0]);
    snprintf(what, sizeof what, "%s at %ld", c->name, f->big);
    m.big = trace_run(plan, b.v, what, f->timeout_s);
    check_output(f, c, &m.big);
    long iters = f->big - f->small;
    m.alloc_h = per_iteration(m.small.alloc, m.big.alloc, iters);
    m.realloc_h = per_iteration(m.small.realloc, m.big.realloc, iters);
    m.dealloc_h = per_iteration(m.small.dealloc, m.big.dealloc, iters);
    return m;
}

static int off(int64_t got, int64_t want, int64_t slack) {
    return got > want + slack || got < want - slack;
}

typedef struct {
    int report;          // hold nothing
    const char *only;    // a prefix of the controls' names, or NULL
    const char *tsv;
} Options;

static int run_check(const char *path, const Options *o) {
    CheckFile f = read_check_file(path);
    int bad = 0, ran = 0;
    char *diff = must_dup("");
    printf("%-30s   allocs at %ld, %ld, an iteration   reallocs an iteration\n", "control", f.small, f.big);
    for (int i = 0; i < f.ncontrols; i++) {
        Control *c = &f.controls[i];
        if (o->only != NULL && !starts_with(c->name, o->only)) continue;
        ran++;
        Measured m = measure(&f, c, 0);
        char big[32] = "-", per[32] = "-", per_re[32] = "-", mark[160] = "";
        int is_off = 0;
        int hold = c->held && !o->report && o->only == NULL;
        if (m.once) {
            if (hold && ((int64_t)m.small.alloc * 100 != c->alloc_h || (int64_t)m.small.realloc * 100 != c->realloc_h)) is_off = 1;
        } else {
            snprintf(big, sizeof big, "%" PRIu64, m.big.alloc);
            hundredths_str(m.alloc_h, per, sizeof per);
            hundredths_str(m.realloc_h, per_re, sizeof per_re);
            if (hold && (off(m.alloc_h, c->alloc_h, f.slack_h) || off(m.realloc_h, c->realloc_h, f.slack_h))) is_off = 1;
        }
        if (hold) snprintf(mark, sizeof mark, "ok");
        if (is_off) {
            char wa[32], wr[32];
            hundredths_str(c->alloc_h, wa, sizeof wa);
            hundredths_str(c->realloc_h, wr, sizeof wr);
            snprintf(mark, sizeof mark, "OFF (held to %s and %s)", wa, wr);
            bad++;
            char got_a[32], got_r[32];
            if (m.once) {
                snprintf(got_a, sizeof got_a, "%" PRIu64, m.small.alloc);
                snprintf(got_r, sizeof got_r, "%" PRIu64, m.small.realloc);
            } else {
                snprintf(got_a, sizeof got_a, "%s", per);
                snprintf(got_r, sizeof got_r, "%s", per_re);
            }
            size_t n = strlen(diff) + strlen(c->name) * 2 + strlen(c->why) + 200;
            char *d = must_alloc(n);
            snprintf(d, n, "%s%s:%d\n- %s %s %s\n+ %s %s %s\n", diff, f.path, c->line, c->name, wa, wr, c->name, got_a, got_r);
            free(diff);
            diff = d;
        }
        printf("%-30s %9" PRIu64 " %9s %9s   %9s   %s\n", c->name, m.small.alloc, big, per, per_re, mark);
        fflush(stdout);
        result_free(&m.small);
        if (!m.once) result_free(&m.big);
    }
    if (ran == 0) fail("%s: no control's name starts with %s", path, o->only);
    if (o->report || o->only != NULL) return 0;
    printf("%d off, of %d controls, held to %s\n", bad, ran, path);
    if (bad > 0) {
        printf("\nwhat the file holds (-) and what ran (+), an iteration, allocs then reallocs:\n%s", diff);
        return EXIT_OFF;
    }
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  " TOOL " count [--small N] [--big M] [--timeout S] -- PROGRAM ARG...\n"
        "  " TOOL " where [--small N] [--big M] [--timeout S] [--tsv FILE] -- PROGRAM ARG...\n"
        "  " TOOL " where [--tsv FILE] [--only PREFIX] CHECKFILE\n"
        "  " TOOL " check [--report] [--only PREFIX] CHECKFILE\n"
        "{N} in an argument is the iteration count; README.md has the rest.\n");
    exit(EXIT_FAIL);
}

static int run_count(CheckFile *f, Control *c) {
    Measured m = measure(f, c, 0);
    if (m.once) {
        printf("%s ran once (no {N} in its arguments)\n", c->run.v[0]);
        printf("allocs %" PRIu64 "  reallocs %" PRIu64 "  deallocs %" PRIu64 "\n", m.small.alloc, m.small.realloc, m.small.dealloc);
        return 0;
    }
    char a[32], r[32], d[32];
    hundredths_str(m.alloc_h, a, sizeof a);
    hundredths_str(m.realloc_h, r, sizeof r);
    hundredths_str(m.dealloc_h, d, sizeof d);
    char at_small[32], at_big[32];
    snprintf(at_small, sizeof at_small, "N=%ld", f->small);
    snprintf(at_big, sizeof at_big, "N=%ld", f->big);
    printf("%-10s %12s %12s %15s\n", "", at_small, at_big, "an iteration");
    printf("%-10s %12" PRIu64 " %12" PRIu64 " %15s\n", "allocs", m.small.alloc, m.big.alloc, a);
    printf("%-10s %12" PRIu64 " %12" PRIu64 " %15s\n", "reallocs", m.small.realloc, m.big.realloc, r);
    printf("%-10s %12" PRIu64 " %12" PRIu64 " %15s\n", "deallocs", m.small.dealloc, m.big.dealloc, d);
    return 0;
}

// ─── Mode `where` ────────────────────────────────────────────────────────

// Where a call site is: the procedure, by its Roc name, and the line.
typedef struct {
    uint64_t site;
    char *proc;
    char *line;   // "" for none
} Place;

typedef struct {
    Place *items;
    size_t n, cap;
} Places;

static const char *before_dot_copy(const char *name, char *buf, size_t n) {
    const char *dot = strchr(name, '.');
    size_t len = dot ? (size_t)(dot - name) : strlen(name);
    if (len >= n) len = n - 1;
    memcpy(buf, name, len);
    buf[len] = 0;
    return buf;
}

static const Place *place_of(const Plan *p, Places *seen, uint64_t site) {
    for (size_t i = 0; i < seen->n; i++) {
        if (seen->items[i].site == site) return &seen->items[i];
    }
    const Proc *pr = proc_at(p, site);
    char symbol[512] = "?";
    const char *proc = "?";
    if (pr != NULL) {
        before_dot_copy(pr->name, symbol, sizeof symbol);
        const char *n = roc_name(p->debug, symbol);
        proc = n != NULL ? n : symbol;
    }
    const char *named = fn_at(p->debug, site);
    if (named == NULL) {
        const Sym *s = func_sym_at(p->exe, site);
        if (s != NULL) named = s->name;
    }
    if (strcmp(proc, symbol) == 0 && named != NULL && !starts_with(named, "roc__")) proc = named;
    char line[600] = "";
    const LineRange *lr = line_at(p->debug, site);
    if (lr != NULL) {
        if (lr->line == 0) snprintf(line, sizeof line, "%s:?", lr->file);
        else snprintf(line, sizeof line, "%s:%" PRIu64, lr->file, lr->line);
    }
    if (seen->n == seen->cap) {
        seen->cap = seen->cap ? seen->cap * 2 : 64;
        seen->items = must_grow(seen->items, seen->cap * sizeof(Place));
    }
    Place *pl = &seen->items[seen->n++];
    pl->site = site;
    pl->proc = must_dup(proc);
    pl->line = must_dup(line);
    return pl;
}

// Whether a place is the Builtin module's own Roc code: its Roc name
// (`Builtin.List.set@U64`) or its line's module says so.
static int is_builtin_code(const Place *pl) {
    return starts_with(pl->proc, "Builtin.") || starts_with(pl->line, "Builtin:");
}

// The place in the program a chain of call sites (the builtin's caller
// first) comes down to: the first that isn't the Builtin module's own Roc
// code, or the first site when every one is, or when the frame pointers
// lead nowhere (a release build may keep none).
static const Place *program_place(const Plan *p, Places *seen, const Sites *s) {
    const Place *first = NULL;
    for (int k = 0; k < CHAIN && (k == 0 || s->at[k] != 0); k++) {
        const Place *pl = place_of(p, seen, s->at[k]);
        if (first == NULL) first = pl;
        if (!is_builtin_code(pl) && strcmp(pl->proc, "?") != 0) return pl;
    }
    return first;
}

// A copying site: a writing builtin and the procedure that entered it.
typedef struct {
    char *builtin, *proc;
    uint64_t small, big, allocs, bytes;
    char **lines;
    size_t nlines;
} CopySite;

typedef struct {
    CopySite *items;
    size_t n;
} CopySites;

static CopySite *copy_site(CopySites *cs, const char *builtin, const char *proc) {
    for (size_t i = 0; i < cs->n; i++) {
        if (strcmp(cs->items[i].builtin, builtin) == 0 && strcmp(cs->items[i].proc, proc) == 0) return &cs->items[i];
    }
    cs->items = must_grow(cs->items, (cs->n + 1) * sizeof(CopySite));
    CopySite *s = &cs->items[cs->n++];
    memset(s, 0, sizeof *s);
    s->builtin = must_dup(builtin);
    s->proc = must_dup(proc);
    return s;
}

static void add_site_line(CopySite *s, const char *line) {
    if (line[0] == 0) return;
    for (size_t i = 0; i < s->nlines; i++) {
        if (strcmp(s->lines[i], line) == 0) return;
    }
    s->lines = must_grow(s->lines, (s->nlines + 1) * sizeof(char *));
    s->lines[s->nlines++] = must_dup(line);
}

// A run's allocations through a writing builtin, by builtin and procedure:
// a procedure, not a site, since a release build calls one write from
// several sites, and which runs depends on the input.
static void collect(const Plan *p, Places *seen, const RunResult *r, CopySites *cs, int big) {
    for (int i = 0; i < TABLE; i++) {
        const Slot *s = &r->table[i];
        if (!s->used || s->what != W_VIA || s->kind != KIND_ALLOC || s->id < 0) continue;
        const char *builtin = short_name(p->entry_names[s->id]);
        if (!is_writer(builtin)) continue;
        const Place *pl = program_place(p, seen, &s->sites);
        CopySite *site = copy_site(cs, builtin, pl->proc);
        if (big) site->big += s->count;
        else site->small += s->count;
        site->allocs += s->count;
        site->bytes += s->bytes;
        add_site_line(site, pl->line);
    }
}

static int compare_strs(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int compare_copy_sites(const void *a, const void *b) {
    const CopySite *x = a, *y = b;
    int k = strcmp(x->builtin, y->builtin);
    return k != 0 ? k : strcmp(x->proc, y->proc);
}

static int run_where(CheckFile *f, const Options *o) {
    FILE *tsv = NULL;
    if (o->tsv != NULL) {
        tsv = fopen(o->tsv, "w");
        if (tsv == NULL) fail("%s: %s", o->tsv, strerror(errno));
        fprintf(tsv, "run\tbuiltin\tcount\tbytes\tprocedure\tline\n");
    }
    int rows = 0, ran = 0;
    size_t watched = 0;
    for (int i = 0; i < f->ncontrols; i++) {
        Control *c = &f->controls[i];
        if (o->only != NULL && !starts_with(c->name, o->only)) continue;
        ran++;
        Measured m = measure(f, c, 1);
        Plan *plan = cached_plan(argv_for(c, 0, f->small, f->big).v[0], 1);
        watched = plan->nentries;
        Places seen = {NULL, 0, 0};
        CopySites cs = {NULL, 0};
        collect(plan, &seen, &m.small, &cs, 0);
        if (!m.once) collect(plan, &seen, &m.big, &cs, 1);
        if (m.once) {
            printf("%s: %" PRIu64 " allocs, %" PRIu64 " reallocs in all\n", c->name, m.small.alloc, m.small.realloc);
        } else {
            char a[32], r[32];
            hundredths_str(m.alloc_h, a, sizeof a);
            hundredths_str(m.realloc_h, r, sizeof r);
            printf("%s: %s allocs and %s reallocs an iteration in all\n", c->name, a, r);
        }
        qsort(cs.items, cs.n, sizeof *cs.items, compare_copy_sites);
        for (size_t k = 0; k < cs.n; k++) {
            CopySite *s = &cs.items[k];
            // For a run with a loop, what one more iteration allocates
            // through the site, from half a copy up; for one without, all.
            int64_t h = m.once ? (int64_t)s->small * 100 : per_iteration(s->small, s->big, f->big - f->small);
            if (!m.once && h < 50) continue;
            char n[32];
            hundredths_str(h, n, sizeof n);
            uint64_t size = s->bytes / (s->allocs ? s->allocs : 1);
            qsort(s->lines, s->nlines, sizeof *s->lines, compare_strs);
            size_t llen = 8;
            for (size_t q = 0; q < s->nlines; q++) llen += strlen(s->lines[q]) + 2;
            char *line = must_alloc(llen);
            if (s->nlines == 0) strcpy(line, "no line");
            for (size_t q = 0; q < s->nlines; q++) {
                if (q > 0) strcat(line, ", ");
                strcat(line, s->lines[q]);
            }
            printf("%s: %s %s of %" PRIu64 " bytes from %s (%s)\n", c->name, s->builtin, n, size, s->proc, line);
            if (tsv != NULL) fprintf(tsv, "%s\t%s\t%s\t%" PRIu64 "\t%s\t%s\n", c->name, s->builtin, n, size, s->proc, line);
            rows++;
            free(line);
        }
        fflush(stdout);
        result_free(&m.small);
        if (!m.once) result_free(&m.big);
    }
    if (ran == 0) fail("%s: no control's name starts with %s", f->path, o->only);
    printf("%d copying sites over %d runs; %zu builtins watched\n", rows, ran, watched);
    if (tsv != NULL && fclose(tsv) != 0) fail("%s: %s", o->tsv, strerror(errno));
    return 0;
}

// ─── The command line ────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 2) usage();
    const char *mode = argv[1];
    if (strcmp(mode, "count") != 0 && strcmp(mode, "where") != 0 && strcmp(mode, "check") != 0) usage();
    Options o = {0, NULL, NULL};
    CheckFile f;
    memset(&f, 0, sizeof f);
    f.path = "the command line";
    f.small = 1000;
    f.big = 10000;
    f.slack_h = 5;
    f.timeout_s = 600;
    int sized = 0, i = 2, program = 0;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            i++;
            program = 1;
            break;
        }
        if (a[0] != '-') break;
        int last = i + 1 >= argc;
        if (strcmp(a, "--report") == 0 && strcmp(mode, "check") == 0) o.report = 1;
        else if (strcmp(a, "--small") == 0 && !last) { f.small = atol(argv[++i]); sized = 1; }
        else if (strcmp(a, "--big") == 0 && !last) { f.big = atol(argv[++i]); sized = 1; }
        else if (strcmp(a, "--timeout") == 0 && !last) f.timeout_s = (unsigned)atol(argv[++i]);
        else if (strcmp(a, "--only") == 0 && !last) o.only = argv[++i];
        else if (strcmp(a, "--tsv") == 0 && !last && strcmp(mode, "where") == 0) o.tsv = argv[++i];
        else fail("%s does not take %s", mode, a);
    }
    if (i >= argc) usage();
    // A program follows `--`; `where` without one takes a check file.
    if (strcmp(mode, "count") == 0 && !program) fail("count runs the program after `--`: " TOOL " count -- ./app {N}");
    if (strcmp(mode, "check") == 0 || (strcmp(mode, "where") == 0 && !program)) {
        if (program || i != argc - 1) usage();
        if (sized) fail("a check file names its own sizes (`small` and `big` lines)");
        if (strcmp(mode, "check") == 0) return run_check(argv[i], &o);
        CheckFile cf = read_check_file(argv[i]);
        return run_where(&cf, &o);
    }
    if (f.small < 0 || f.big <= f.small) fail("--big (%ld) must be more than --small (%ld)", f.big, f.small);
    Control c;
    memset(&c, 0, sizeof c);
    const char *slash = strrchr(argv[i], '/');
    c.name = slash != NULL ? (char *)slash + 1 : argv[i];
    for (int k = i; k < argc; k++) argv_push(&c.run, argv[k]);
    c.shape = has_n(&c.run) ? SHAPE_TEMPLATE : SHAPE_ONCE;
    c.why = "";
    f.controls = &c;
    f.ncontrols = 1;
    if (strcmp(mode, "count") == 0) return run_count(&f, &c);
    return run_where(&f, &o);
}
