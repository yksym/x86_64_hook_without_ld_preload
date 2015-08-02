/*
 * This file is part of ltrace.
 * Copyright (C) 2006,2010,2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Zachary T Welch, CodeSourcery
 * Copyright (C) 2010 Joe Damato
 * Copyright (C) 1997,1998,2001,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Olaf Hering, SUSE Linux GmbH
 * Copyright (C) 2006 Eric Vaitl, Cisco Systems, Inc.
 * Copyright (C) 2006 Paul Gilliam, IBM Corporation
 * Copyright (C) 2006 Ian Wienand
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <assert.h>
#ifdef	__linux__
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include "library.h"
//
typedef void *arch_addr_t;

struct arch_ltelf_data {
};

struct ltelf {
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Data *dynsym;
	size_t dynsym_count;
	const char *dynstr;
	GElf_Addr plt_addr;
	GElf_Word plt_flags;
	size_t plt_size;
	Elf_Data *relplt;
	Elf_Data *plt_data;
	size_t relplt_count;
	Elf_Data *symtab;
	const char *strtab;
	const char *soname;
	size_t symtab_count;
	Elf_Data *opd;
	GElf_Addr *opd_addr;
	size_t opd_size;
	GElf_Addr dyn_addr;
	size_t dyn_sz;
	size_t relplt_size;
	GElf_Addr bias;
	GElf_Addr entry_addr;
	GElf_Addr base_addr;
	struct arch_ltelf_data arch;
};

Elf_Data *
elf_loaddata(Elf_Scn *scn, GElf_Shdr *shdr)
{
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL || elf_getdata(scn, data) != NULL
	    || data->d_off || data->d_size != shdr->sh_size)
		return NULL;
	return data;
}

static int
elf_get_section_if(struct ltelf *lte, Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr,
		   int (*predicate)(Elf_Scn *, GElf_Shdr *, void *data),
		   void *data)
{
	int i;
	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;

		scn = elf_getscn(lte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			return -1;
		}
		if (predicate(scn, &shdr, data)) {
			*tgt_sec = scn;
			*tgt_shdr = shdr;
			return 0;
		}
	}
	return -1;

}

static int
inside_p(Elf_Scn *scn, GElf_Shdr *shdr, void *data)
{
	GElf_Addr addr = *(GElf_Addr *)data;
	return addr >= shdr->sh_addr
		&& addr < shdr->sh_addr + shdr->sh_size;
}

int
elf_get_section_covering(struct ltelf *lte, GElf_Addr addr,
			 Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &inside_p, &addr);
}

static int
type_p(Elf_Scn *scn, GElf_Shdr *shdr, void *data)
{
	GElf_Word type = *(GElf_Word *)data;
	return shdr->sh_type == type;
}

int
elf_get_section_type(struct ltelf *lte, GElf_Word type,
		     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &type_p, &type);
}

struct section_named_data {
	struct ltelf *lte;
	const char *name;
};

static int
name_p(Elf_Scn *scn, GElf_Shdr *shdr, void *d)
{
	struct section_named_data *data = d;
	const char *name = elf_strptr(data->lte->elf,
				      data->lte->ehdr.e_shstrndx,
				      shdr->sh_name);
	return strcmp(name, data->name) == 0;
}

int
elf_get_section_named(struct ltelf *lte, const char *name,
		     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	struct section_named_data data = {
		.lte = lte,
		.name = name,
	};
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &name_p, &data);
}

static int
need_data(Elf_Data *data, GElf_Xword offset, GElf_Xword size)
{
	assert(data != NULL);
	if (data->d_size < size || offset > data->d_size - size) {
		return -1;
	}
	return 0;
}

#define DEF_READER(NAME, SIZE)						\
	int								\
	NAME(Elf_Data *data, GElf_Xword offset, uint##SIZE##_t *retp)	\
	{								\
		if (!need_data(data, offset, SIZE / 8) < 0)		\
			return -1;					\
									\
		if (data->d_buf == NULL) /* NODATA section */ {		\
			*retp = 0;					\
			return 0;					\
		}							\
									\
		union {							\
			uint##SIZE##_t dst;				\
			char buf[0];					\
		} u;							\
		memcpy(u.buf, data->d_buf + offset, sizeof(u.dst));	\
		*retp = u.dst;						\
		return 0;						\
	}

DEF_READER(elf_read_u16, 16)
DEF_READER(elf_read_u32, 32)
DEF_READER(elf_read_u64, 64)

#undef DEF_READER

int
open_elf(struct ltelf *lte, const char *filename)
{
	lte->fd = open(filename, O_RDONLY);
	if (lte->fd == -1)
		return 1;

	elf_version(EV_CURRENT);

#ifdef HAVE_ELF_C_READ_MMAP
	lte->elf = elf_begin(lte->fd, ELF_C_READ_MMAP, NULL);
#else
	lte->elf = elf_begin(lte->fd, ELF_C_READ, NULL);
#endif

	if (lte->elf == NULL || elf_kind(lte->elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", filename);
		exit(EXIT_FAILURE);
	}

	if (gelf_getehdr(lte->elf, &lte->ehdr) == NULL) {
		fprintf(stderr, "can't read ELF header of \"%s\": %s\n",
			filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	if (lte->ehdr.e_type != ET_EXEC && lte->ehdr.e_type != ET_DYN) {
		fprintf(stderr, "\"%s\" is neither an ELF executable"
			" nor a shared library\n", filename);
		exit(EXIT_FAILURE);
	}

	if (1
#ifdef LT_ELF_MACHINE
	    && (lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS
		|| lte->ehdr.e_machine != LT_ELF_MACHINE)
#endif
#ifdef LT_ELF_MACHINE2
	    && (lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS2
		|| lte->ehdr.e_machine != LT_ELF_MACHINE2)
#endif
#ifdef LT_ELF_MACHINE3
	    && (lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS3
		|| lte->ehdr.e_machine != LT_ELF_MACHINE3)
#endif
		) {
		fprintf(stderr,
			"\"%s\" is ELF from incompatible architecture\n",
			filename);
		exit(EXIT_FAILURE);
	}

	return 0;
}

static void
read_symbol_table(struct ltelf *lte, const char *filename,
		  Elf_Scn *scn, GElf_Shdr *shdr, const char *name,
		  Elf_Data **datap, size_t *countp, const char **strsp)
{
	*datap = elf_getdata(scn, NULL);
	*countp = shdr->sh_size / shdr->sh_entsize;
	if ((*datap == NULL || elf_getdata(scn, *datap) != NULL)
	    ) {
		fprintf(stderr, "Couldn't get data of section"
			" %s from \"%s\": %s\n",
			name, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	scn = elf_getscn(lte->elf, shdr->sh_link);
	GElf_Shdr shdr2;
	if (scn == NULL || gelf_getshdr(scn, &shdr2) == NULL) {
		fprintf(stderr, "Couldn't get header of section"
			" #%d from \"%s\": %s\n",
			shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL || elf_getdata(scn, data) != NULL
	    || shdr2.sh_size != data->d_size || data->d_off) {
		fprintf(stderr, "Couldn't get data of section"
			" #%d from \"%s\": %s\n",
			shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	*strsp = data->d_buf;
}

static int
do_init_elf(struct ltelf *lte, const char *filename)
{
	int i;
	GElf_Addr relplt_addr = 0;
	GElf_Addr soname_offset = 0;

	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		scn = elf_getscn(lte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			fprintf(stderr,	"Couldn't get section #%d from"
				" \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		name = elf_strptr(lte->elf, lte->ehdr.e_shstrndx, shdr.sh_name);
		if (name == NULL) {
			fprintf(stderr,	"Couldn't get name of section #%d from"
				" \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			read_symbol_table(lte, filename,
					  scn, &shdr, name, &lte->symtab,
					  &lte->symtab_count, &lte->strtab);

		} else if (shdr.sh_type == SHT_DYNSYM) {
			read_symbol_table(lte, filename,
					  scn, &shdr, name, &lte->dynsym,
					  &lte->dynsym_count, &lte->dynstr);

		} else if (shdr.sh_type == SHT_DYNAMIC) {
			Elf_Data *data;
			size_t j;

			lte->dyn_addr = shdr.sh_addr + lte->bias;
			lte->dyn_sz = shdr.sh_size;

			data = elf_getdata(scn, NULL);
			if (data == NULL || elf_getdata(scn, data) != NULL) {
				fprintf(stderr, "Couldn't get .dynamic data"
					" from \"%s\": %s\n",
					filename, strerror(errno));
				exit(EXIT_FAILURE);
			}

			for (j = 0; j < shdr.sh_size / shdr.sh_entsize; ++j) {
				GElf_Dyn dyn;

				if (gelf_getdyn(data, j, &dyn) == NULL) {
					fprintf(stderr, "Couldn't get .dynamic"
						" data from \"%s\": %s\n",
						filename, strerror(errno));
					exit(EXIT_FAILURE);
				}
				if (dyn.d_tag == DT_JMPREL)
					relplt_addr = dyn.d_un.d_ptr;
				else if (dyn.d_tag == DT_PLTRELSZ)
					lte->relplt_size = dyn.d_un.d_val;
				else if (dyn.d_tag == DT_SONAME)
					soname_offset = dyn.d_un.d_val;
			}
		} else if (shdr.sh_type == SHT_PROGBITS
			   || shdr.sh_type == SHT_NOBITS) {
			if (strcmp(name, ".plt") == 0) {
				lte->plt_addr = shdr.sh_addr;
				lte->plt_size = shdr.sh_size;
				lte->plt_data = elf_loaddata(scn, &shdr);
				if (lte->plt_data == NULL)
					fprintf(stderr,
						"Can't load .plt data\n");
				lte->plt_flags = shdr.sh_flags;
			}
#ifdef ARCH_SUPPORTS_OPD
			else if (strcmp(name, ".opd") == 0) {
				lte->opd_addr = (GElf_Addr *) (long) shdr.sh_addr;
				lte->opd_size = shdr.sh_size;
				lte->opd = elf_rawdata(scn, NULL);
			}
#endif
		}
	}

	if (lte->dynsym == NULL || lte->dynstr == NULL) {
		fprintf(stderr, "Couldn't find .dynsym or .dynstr in \"%s\"\n",
			filename);
		exit(EXIT_FAILURE);
	}

	if (!relplt_addr || !lte->plt_addr) {
		lte->relplt = NULL;
		lte->relplt_count = 0;
	} else if (lte->relplt_size == 0) {
		lte->relplt = NULL;
		lte->relplt_count = 0;
	} else {

		for (i = 1; i < lte->ehdr.e_shnum; ++i) {
			Elf_Scn *scn;
			GElf_Shdr shdr;

			scn = elf_getscn(lte->elf, i);
			if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
				fprintf(stderr, "Couldn't get section header"
					" from \"%s\": %s\n",
					filename, elf_errmsg(-1));
				exit(EXIT_FAILURE);
			}
			if (shdr.sh_addr == relplt_addr
			    && shdr.sh_size == lte->relplt_size) {
				lte->relplt = elf_getdata(scn, NULL);
				lte->relplt_count =
				    shdr.sh_size / shdr.sh_entsize;
				if (lte->relplt == NULL
				    || elf_getdata(scn, lte->relplt) != NULL) {
					fprintf(stderr, "Couldn't get .rel*.plt"
						" data from \"%s\": %s\n",
						filename, elf_errmsg(-1));
					exit(EXIT_FAILURE);
				}
				break;
			}
		}

		if (i == lte->ehdr.e_shnum) {
			fprintf(stderr,
				"Couldn't find .rel*.plt section in \"%s\"\n",
				filename);
			exit(EXIT_FAILURE);
		}

	}

	if (soname_offset != 0)
		lte->soname = lte->dynstr + soname_offset;

	return 0;
}

void
do_close_elf(struct ltelf *lte)
{
	elf_end(lte->elf);
	close(lte->fd);
}

int
elf_get_sym_info(struct ltelf *lte, const char *filename,
		 size_t sym_index, GElf_Rela *rela, GElf_Sym *sym)
{
	int i = sym_index;
	GElf_Rel rel;
	void *ret;

	if (lte->relplt->d_type == ELF_T_REL) {
		ret = gelf_getrel(lte->relplt, i, &rel);
		rela->r_offset = rel.r_offset;
		rela->r_info = rel.r_info;
		rela->r_addend = 0;
	} else {
		ret = gelf_getrela(lte->relplt, i, rela);
	}

	if (ret == NULL
	    || ELF64_R_SYM(rela->r_info) >= lte->dynsym_count
	    || gelf_getsym(lte->dynsym, ELF64_R_SYM(rela->r_info),
			   sym) == NULL) {
		fprintf(stderr,
			"Couldn't get relocation from \"%s\": %s\n",
			filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	return 0;
}

#ifndef ARCH_HAVE_GET_SYMINFO
int
arch_get_sym_info(struct ltelf *lte, const char *filename,
		  size_t sym_index, GElf_Rela *rela, GElf_Sym *sym)
{
	return elf_get_sym_info(lte, filename, sym_index, rela, sym);
}
#endif

GElf_Addr arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela * rela) {
	return lte->plt_addr + (ndx + 1) * 16;
}

static void* get_plt_addr( const char *filename,
        const char* funcname,
	     struct ltelf *lte,
	     int latent_plts)
{
	size_t i;
	for (i = 0; i < lte->relplt_count; ++i) {
		GElf_Rela rela;
		GElf_Sym sym;

		if (arch_get_sym_info(lte, filename, i, &rela, &sym) < 0)
			continue; /* Skip this entry.  */

		char const *name = lte->dynstr + sym.st_name;
        if (strcmp(name, funcname) == 0) {
            GElf_Addr addr = arch_plt_sym_val(lte, i, &rela);
            return (void*) (uintptr_t)(addr + lte->bias);
        }
	}
	return NULL;
}

void* getPLTAddrFromElf(const char *filename, const char* funcname, GElf_Addr bias)
{
	struct ltelf lte = {};
	if (open_elf(&lte, filename) < 0)
		return NULL;

	{
		GElf_Phdr phdr;
		size_t i;
		for (i = 0; gelf_getphdr (lte.elf, i, &phdr) != NULL; ++i) {
			if (phdr.p_type == PT_LOAD) {
				lte.base_addr = phdr.p_vaddr + bias;
				break;
			}
		}

		lte.bias = bias;
		lte.entry_addr = lte.ehdr.e_entry + lte.bias;

		if (lte.base_addr == 0) {
			return NULL;
		}
	}

	if (do_init_elf(&lte, filename) < 0)
		return NULL;

    void* ret = get_plt_addr(filename, funcname, &lte,  0);

	do_close_elf(&lte);
	return ret;
}


