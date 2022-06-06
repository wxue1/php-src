/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Andi Gutmans <andi@php.net>                                 |
   |          Zeev Suraski <zeev@php.net>                                 |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@php.net>                              |
   +----------------------------------------------------------------------+
*/

#include "zend_shared_alloc.h"

#ifdef USE_MMAP

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#ifdef __APPLE__
#include <mach/vm_statistics.h>
#endif

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
# define MAP_ANONYMOUS MAP_ANON
#endif
#if defined(MAP_ALIGNED_SUPER)
# define MAP_HUGETLB MAP_ALIGNED_SUPER
#endif

/* On Linux OS, this function returns the start address of the first PHP segment
   through parsing /proc/self/maps file; on any other OSes, simply returns NULL.
*/
static void* get_php_start_addr(void)
{
#if defined(__linux__)
	/* Used to parse each field for the line in /proc/self/maps file */
	long unsigned int start, end, offset, inode;
	char perm[5], dev[10], name[MAXPATHLEN];
	int ret;
	FILE *f = NULL;

	f = fopen("/proc/self/maps", "r");
	if (!f) {
		return NULL;
	}

	/* Only get the start address of the first PHP segment */
	ret = fscanf(f, "%lx-%lx %4s %lx %9s %ld %s\n",
					&start, &end, perm, &offset, dev, &inode, name);
	fclose(f); f=NULL;

	/* Expect to get seven fields */
	if (7 == ret) {
		return (void*)start;
	}
#endif /* __linux__ */
	return NULL;
}

static int create_segments(size_t requested_size, zend_shared_segment ***shared_segments_p, int *shared_segments_count, char **error_in)
{
	zend_shared_segment *shared_segment;
	int flags = PROT_READ | PROT_WRITE, fd = -1;
	void *p;
    
    void *php_start_addr = NULL; /* start address of first PHP segment */
	void *preferred_mmap_addr = NULL; /* for mmap() */

	long unsigned int huge_page_size = 2 * 1024 * 1024; /* 2MB page size */
	long unsigned int ordinary_page_size = 4 * 1024; /* 4KB page size */

#ifdef MAP_HUGETLB
	long unsigned int one_page_hole = huge_page_size;	/* 2MB */
#else
	long unsigned int one_page_hole = 4 * 1024; /* 4KB */
#endif /* MAP_HUGETLB */

#ifdef PROT_MPROTECT
	flags |= PROT_MPROTECT(PROT_EXEC);
#endif
#ifdef VM_MAKE_TAG
	/* allows tracking segments via tools such as vmmap */
	fd = VM_MAKE_TAG(251U);
#endif
#ifdef PROT_MAX
	flags |= PROT_MAX(PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

	/* Try to allocate memory just prior to PHP segments.
	   This way can benefit 'near jump' efficiency between JIT buffer and
	   other .text segments, and potentially offer PHP ~2% more performance.
	*/

	php_start_addr = get_php_start_addr();

	/* Do mmap allocation with preferred address only if
	   1) PHP starts from above 4GB address
	   2) Enough free space before PHP segments
	      (Reserve one page hole for memory address alignment)
	*/
	if (php_start_addr &&
		((long unsigned int) php_start_addr > UINT_MAX) &&
		(((long unsigned int) php_start_addr - one_page_hole) > requested_size))
	{
		/* Calculate the preferred mapping address */
		preferred_mmap_addr = php_start_addr - requested_size - one_page_hole;
	}

#ifdef MAP_HUGETLB
	/* Try to allocate huge pages first to reduce dTLB misses.
	 * OSes has to be configured properly
	 * on Linux
	 * (e.g. https://wiki.debian.org/Hugepages#Enabling_HugeTlbPage)
	 * You may verify huge page usage with the following command:
	 * `grep "Huge" /proc/meminfo`
	 * on FreeBSD
	 * sysctl vm.pmap.pg_ps_enabled entry
	 * (boot time config only, but enabled by default on most arches).
	 */
	if (requested_size >= huge_page_size && requested_size % huge_page_size == 0) {
#if defined(__x86_64__) && defined(__linux__)
		/* On 64b Linux, we first try to allocate segment in 2MB huge pages,
		   and then in ordinary 4KB pages with preferred mapping address.
		   If both faled, fall back without preferred mapping address
		   (ie. previous mmap calling).
		*/

		/* Try to allocate huge pages using preferred address */
		preferred_mmap_addr = (void*)(ZEND_MM_ALIGNED_SIZE_EX((ptrdiff_t)preferred_mmap_addr, huge_page_size));
		p = mmap(preferred_mmap_addr, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, fd, 0);
		if (p != MAP_FAILED) {
            fprintf(stderr, "Mmap JIT buffer into huge pages near php text\n");
			goto success;
		}

		/* Try to allocate 4KB pages because huge page allocation failed */
		preferred_mmap_addr = (void*)(ZEND_MM_ALIGNED_SIZE_EX((ptrdiff_t)preferred_mmap_addr, ordinary_page_size));
		p = mmap(preferred_mmap_addr, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS, fd, 0);
		if (p != MAP_FAILED) {
			goto success;
		}
#endif /* __x86_64__ && __linux__ */

# if defined(__x86_64__) && defined(MAP_32BIT)
		/* to got HUGE PAGES in low 32-bit address we have to reserve address
		   space and then remap it using MAP_HUGETLB */

		p = mmap(NULL, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_32BIT, fd, 0);
		if (p != MAP_FAILED) {
			munmap(p, requested_size);
			p = (void*)(ZEND_MM_ALIGNED_SIZE_EX((ptrdiff_t)p, huge_page_size));
			p = mmap(p, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_32BIT|MAP_HUGETLB|MAP_FIXED, -1, 0);
			if (p != MAP_FAILED) {
				goto success;
			} else {
				p = mmap(NULL, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_32BIT, fd, 0);
				if (p != MAP_FAILED) {
					goto success;
				}
			}
		}
# endif /* __x86_64__ && MAP_32BIT */
		p = mmap(0, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, fd, 0);
		if (p != MAP_FAILED) {
			goto success;
		}
	}
#elif defined(PREFER_MAP_32BIT) && defined(__x86_64__) && defined(MAP_32BIT)
	p = mmap(NULL, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_32BIT, fd, 0);
	if (p != MAP_FAILED) {
		goto success;
	}
#endif /* MAP_HUGETLB */

	/* Allocate 4KB pages because huge page is not supported. */
#if defined(__x86_64__) && defined(__linux__)
	/* On 64b Linux, try to allocate segment using preferred address;
	   if failed, fall through to previous allocation logic. */
	preferred_mmap_addr = (void*)(ZEND_MM_ALIGNED_SIZE_EX((ptrdiff_t)preferred_mmap_addr, ordinary_page_size));
	p = mmap(preferred_mmap_addr, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS, fd, 0);
	if (p != MAP_FAILED) {
		goto success;
	}
#endif /* __x86_64__&& __linux__ */

	p = mmap(0, requested_size, flags, MAP_SHARED|MAP_ANONYMOUS, fd, 0);
	if (p == MAP_FAILED) {
		*error_in = "mmap";
		return ALLOC_FAILURE;
	}

success: ZEND_ATTRIBUTE_UNUSED;
	*shared_segments_count = 1;
	*shared_segments_p = (zend_shared_segment **) calloc(1, sizeof(zend_shared_segment) + sizeof(void *));
	if (!*shared_segments_p) {
		munmap(p, requested_size);
		*error_in = "calloc";
		return ALLOC_FAILURE;
	}
	shared_segment = (zend_shared_segment *)((char *)(*shared_segments_p) + sizeof(void *));
	(*shared_segments_p)[0] = shared_segment;

	shared_segment->p = p;
	shared_segment->pos = 0;
	shared_segment->size = requested_size;

	return ALLOC_SUCCESS;
}

static int detach_segment(zend_shared_segment *shared_segment)
{
	munmap(shared_segment->p, shared_segment->size);
	return 0;
}

static size_t segment_type_size(void)
{
	return sizeof(zend_shared_segment);
}

zend_shared_memory_handlers zend_alloc_mmap_handlers = {
	create_segments,
	detach_segment,
	segment_type_size
};

#endif /* USE_MMAP */
