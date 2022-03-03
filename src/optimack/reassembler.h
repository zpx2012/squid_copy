// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include <cstdint>
#include <sys/types.h>
#include <stdint.h>

inline size_t pad_size(size_t size)
	{
	// We emulate glibc here (values measured on Linux i386).
	// FIXME: We should better copy the portable value definitions from glibc.
	if ( size == 0 )
		return 0;	// glibc allocated 16 bytes anyway.

	const int pad = 8;
	if ( size < 12 )
		return 2 * pad;

	return ((size+3) / pad + 1) * pad;
	}

#define padded_sizeof(x) (pad_size(sizeof(x)))

// Whenever subclassing the Reassembler class
// you should add to this for known subclasses.
enum ReassemblerType {
	REASSEM_UNKNOWN,
	REASSEM_TCP,
	REASSEM_FRAG,
	REASSEM_FILE,

	// Terminal value. Add new above.
	REASSEM_NUM,
};

class Reassembler;

class DataBlock {
public:
	DataBlock(Reassembler* reass, const u_char* data,
	          uint64_t size, uint64_t seq,
	          DataBlock* prev, DataBlock* next,
	          ReassemblerType reassem_type = REASSEM_UNKNOWN);

	~DataBlock();

	uint64_t Size() const	{ return upper - seq; }

	DataBlock* next;	// next block with higher seq #
	DataBlock* prev;	// previous block with lower seq #
	uint64_t seq, upper;
	u_char* block;
	ReassemblerType rtype;

	Reassembler* reassembler; // Non-owning pointer back to parent.
};

class Reassembler {
public:
	Reassembler() {};
	Reassembler(uint64_t init_seq, ReassemblerType reassem_type = REASSEM_UNKNOWN);
	~Reassembler();

	void NewBlock(uint64_t seq, uint64_t len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	uint64_t TrimToSeq(uint64_t seq);

	// Delete all held blocks.
	void ClearBlocks();
	void ClearOldBlocks();

	int HasBlocks() const		{ return blocks != 0; }
	uint64_t LastReassemSeq() const	{ return last_reassem_seq; }

	uint64_t TotalSize() const;	// number of bytes buffered up
	int InOrderStrs(u_char* &buf, int buf_len);
	// void Describe(ODesc* d) const override;

	// Sum over all data buffered in some reassembler.
	static uint64_t TotalMemoryAllocation()	{ return total_size; }

	// Data buffered by type of reassembler.
	static uint64_t MemoryAllocation(ReassemblerType rtype);

	void SetMaxOldBlocks(uint32_t count)	{ max_old_blocks = count; }

protected:

	friend class DataBlock;

	void Undelivered(uint64_t up_to_seq);

	// virtual void BlockInserted(DataBlock* b) = 0;
	// virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

	DataBlock* AddAndCheck(DataBlock* b, uint64_t seq,
				uint64_t upper, const u_char* data);

	void CheckOverlap(DataBlock *head, DataBlock *tail,
				uint64_t seq, uint64_t len, const u_char* data);

	DataBlock* blocks;
	DataBlock* last_block;

	DataBlock* old_blocks;
	DataBlock* last_old_block;

	uint64_t last_reassem_seq;
	uint64_t trim_seq;	// how far we've trimmed
	uint32_t max_old_blocks;
	uint32_t total_old_blocks;
	uint64_t size_of_all_blocks;

	ReassemblerType rtype;

	static uint64_t total_size;
	static uint64_t sizes[REASSEM_NUM];
};

inline DataBlock::~DataBlock()
	{
	reassembler->size_of_all_blocks -= Size();
	Reassembler::total_size -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	Reassembler::sizes[rtype] -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	delete [] block;
	}

#endif
