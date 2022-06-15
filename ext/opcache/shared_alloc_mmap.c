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

#if defined(__x86_64__) && defined(__linux__)
#define max(a,b) ((a) > (b) ? (a):(b))
ZEND_API void* php_text_lighthouse();

static const size_t ordinary_page_size = 4 * 1024; /* 4KB page size */
/* 2MB page size */
static const size_t huge_page_size = 2 * 1024 * 1024;
/* 4GB address distance */
static const size_t addr_distance = 4UL * 1024 * 1024 * 1024;
/* Store the segment in maps file */
struct map_seg_addresses {
    uintptr_t start;
    uintptr_t end;
};

/* Read line number in maps file */
static int map_segment_count() {
    FILE *f = NULL;
    f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    int count = 0;
    char buffer[MAXPATHLEN];
    while ((fgets(buffer, MAXPATHLEN, f)) != NULL) {
        count++;
    }
    fclose(f);
    f = NULL;
    return count;
}

/* Store segments in array and find the php text segment */
static void parse_map_file(struct map_seg_addresses* map_segments,
                          struct map_seg_addresses* php_text_segment) {
    char buffer[MAXPATHLEN];
    FILE *f = NULL;
    f = fopen("/proc/self/maps", "r");
    if (!f) return NULL;
    int index = 0;
    void* start;
    void* end;
    
    /* Get an func address to locate PHP text segment */
    void* zend_code_addr = php_text_lighthouse();

    /* Store each line in tha map_segments array */
    while (fgets(buffer, MAXPATHLEN, f)) {
        if (sscanf(buffer, "%p-%p", &start, &end)) {
            map_segments[index].start = (uintptr_t)start;
            map_segments[index].end = (uintptr_t)end;
            index++;
        }
        if ((uintptr_t)zend_code_addr > (uintptr_t)start && zend_code_addr < (uintptr_t)end) {
            php_text_segment->start = (uintptr_t)start;
            php_text_segment->end = (uintptr_t)end;
        }
    }
    fclose(f);
    f = NULL;
}

/* Insert sort all segments in maps file by the start address.
* The segments is in ascending order finally. */
static void inssort(struct map_seg_addresses* segments, int len) {
    struct map_seg_addresses temp;
    for (int i = 1; i < len; i++) {
        for (int j = i; (j > 0) && (segments[j].start < segments[j-1].start); j--) {
            temp.start = segments[j].start;
            temp.end = segments[j].end;
            segments[j].start = segments[j-1].start;
            segments[j].end = segments[j-1].end;
            segments[j-1].start = temp.start;
            segments[j-1].end = temp.end;
        }
    }
}

/* Merge continous segments and final res has no overlapping segments.
 * Return the count of all isolated segments.
*/
static int merge_continous_segment(struct map_seg_addresses* segments,
                            int len, 
                            struct map_seg_addresses* res) {
    int res_len = 0;
    for (int i = 0; i < len;) {
        res[res_len].start = segments[i].start;
        /* temp remember the biggest end address of continous segments. */
        uintptr_t temp = segments[i].end;
        int j = i + 1;
        /* As long as segments[j] is continous, we update temp value */
        while (j < len && segments[j].start <= temp) {
            temp = max(temp, segments[j].end);
            j++;
        }
        res[res_len].end = temp;
        res_len++;
        i = j;
    }
    return res_len;
}

/* Search all candidate addresses to mmap opcache and jit_buffer.
* All available addresses are stored in candidates array.
* The func returns candidate count */
static int search_candidates(struct map_seg_addresses* merged_segments,
                    int len,
                    size_t requested_size, 
                    struct map_seg_addresses* php_text_segment,
                    uintptr_t* candidates) 
{
    uintptr_t last_end = UINT32_MAX;
    uintptr_t candidate = NULL;
    int candidate_count = 0;
    size_t reserved_align_space = ordinary_page_size;
#if defined(MAP_HUGETLB)
        reserved_align_space = huge_page_size;
#endif /* MAP_HUGETLB */

    for (int i = 0; i < len; i++) {
        /* condition1: the unallocated space is greater than 
        * the sum of requested_size and reserved_align_space */
        if (merged_segments[i].start - last_end > requested_size + reserved_align_space) {
            /* condition2: the longest jump distance between candidate and php segment is less than 4GB.
            * Here are two different candidates addresses:
            * One is merged_segments.start - reserved_align_space - requested_size to merged_segments.start
            * Another one is merged_segments.end to merged_segments.end + requested_size + reserved_align_space*/
            if (merged_segments[i].start <= php_text_segment->start) {
                candidate = merged_segments[i].start - reserved_align_space - requested_size;
                candidate = ZEND_MM_ALIGNED_SIZE_EX(candidate, reserved_align_space);
                if (php_text_segment->end - candidate < addr_distance) {
                    candidates[candidate_count] = candidate;
                    candidate_count++;
                }
            }
            if (merged_segments[i].start >= php_text_segment->end) {
                candidate = last_end;
                candidate = ZEND_MM_ALIGNED_SIZE_EX(candidate, reserved_align_space);
                if (candidate + requested_size + reserved_align_space - php_text_segment->start < addr_distance) {
                    candidates[candidate_count] = candidate;
                    candidate_count++;
                }
            }
        }
        last_end = merged_segments[i].end;
    }
    return candidate_count;
}

static void* create_preferred_segments(size_t requested_size) {
    /* If requested_size is larger than 4GB, do not move opcache and jit buffer */
    if (requested_size > addr_distance) {
        return NULL;
    }

    /* Get total segments count */
    int segment_count = 0;
    segment_count = map_segment_count();
    if (segment_count == 0) return NULL;

    /* Store segments in array and find the php text segment */
    struct map_seg_addresses map_segments[segment_count];
    struct map_seg_addresses php_text_segment;
    struct map_seg_addresses *php_text = &php_text_segment;
    parse_map_file(map_segments, php_text);

    /* Sort segments by the start address */
    inssort(map_segments, segment_count);

    /* Merge continous segments */
    int merged_segments_count = 0;
    struct map_seg_addresses merged_segments[segment_count];
    merged_segments_count = merge_continous_segment(map_segments, segment_count, merged_segments);
    
    /* Search unallocated address space to get the preferred mmap start addresses*/
    int candidate_count = 0;
    uintptr_t candidates[merged_segments_count + 1];
    candidate_count = search_candidates(merged_segments,
                              merged_segments_count,
                              requested_size, 
                              php_text,
                              candidates);
    if (candidate_count == 0) return NULL;

    /* Create segments by trying all candidate addresses and return immediately if succeed. */
	void *res;
	int flags = PROT_READ | PROT_WRITE, fd = -1;
    /* Try to get memory from huge pages */
#if defined(MAP_HUGETLB)
    for(int i = 0; i < candidate_count; i++) {
		res = mmap((void *)candidates[i], requested_size, flags, MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, fd, 0);
		if (MAP_FAILED != res) {
			return res;
		}
    }
#endif /* MAP_HUGETLB */
    /* Try 4KB pages, e.g., huge page allocation is failed or not supported */
    for(int i = 0; i < candidate_count; i++) {
        res = mmap((void *)candidates[i], requested_size, flags, MAP_SHARED|MAP_ANONYMOUS, fd, 0);
		if (MAP_FAILED != res) {
			return res;
		}
    }
    /* not able to do mmap, e.g.,
    * 1) fail to parse maps file
    * 2) not enough space for allocation, etc. */
    return MAP_FAILED;
}
#endif /* x86_64__ && __linux__ */

/* In this function, we first try to allocate segment memory with a
   preferred start address which near PHP text segment.
   In this way, it can benefit 'near jump' efficiency between JIT buffer and
   other .text segments, and potentially offer PHP ~2% more performance both
   on 2MB huge pages and ordinary 4KB pages. So fare, we only support Linux.
   FIXME(tony): consider support *BSD in future.
*/
static int create_segments(size_t requested_size, zend_shared_segment ***shared_segments_p, int *shared_segments_count, char **error_in)
{
	zend_shared_segment *shared_segment;
	int flags = PROT_READ | PROT_WRITE, fd = -1;
	void *p;
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
		/* On 64b Linux, we first try to allocate preferred segment; if failed,
		   fall back to previous allocation logic: mmap(NULL, ...)
		*/
		p = create_preferred_segments(requested_size);
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
	   if failed, fall through to previous logic. */
	p = create_preferred_segments(requested_size);
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
