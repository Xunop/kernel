// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include <stdlib.h>

#include <linux/objtool.h>

#include <objtool/warn.h>
#include <objtool/orc.h>

int init_orc_entry(struct orc_entry *orc, struct cfi_state *cfi,
		   struct instruction *insn)
{
	struct cfi_reg *bp = &cfi->regs[CFI_BP];

	memset(orc, 0, sizeof(*orc));

	if (!cfi) {
		orc->end = 0;
		orc->sp_reg = ORC_REG_UNDEFINED;
		return 0;
	}

	orc->end = cfi->end;

	if (cfi->cfa.base == CFI_UNDEFINED) {
		orc->sp_reg = ORC_REG_UNDEFINED;
		return 0;
	}

	switch (cfi->cfa.base) {
	case CFI_SP:
		orc->sp_reg = ORC_REG_SP;
		break;
	case CFI_SP_INDIRECT:
		orc->sp_reg = ORC_REG_SP_INDIRECT;
		break;
	case CFI_BP:
		orc->sp_reg = ORC_REG_BP;
		break;
	case CFI_BP_INDIRECT:
		orc->sp_reg = ORC_REG_BP_INDIRECT;
		break;
	default:
		WARN_FUNC("unknown CFA base reg %d",
			  insn->sec, insn->offset, cfi->cfa.base);
		return -1;
	}

	switch (bp->base) {
	case CFI_UNDEFINED:
		orc->bp_reg = ORC_REG_UNDEFINED;
		break;
	case CFI_CFA:
		orc->bp_reg = ORC_REG_PREV_SP;
		break;
	case CFI_BP:
		orc->bp_reg = ORC_REG_BP;
		break;
	default:
		WARN_FUNC("unknown BP base reg %d",
			  insn->sec, insn->offset, bp->base);
		return -1;
	}

	orc->sp_offset = cfi->cfa.offset;
	orc->bp_offset = bp->offset;
	orc->type = cfi->type;

	return 0;
}

static const char *reg_name(unsigned int reg)
{
	switch (reg) {
	case ORC_REG_PREV_SP:
		return "prevsp";
	case ORC_REG_BP:
		return "fp";
	case ORC_REG_SP:
		return "sp";
	case ORC_REG_BP_INDIRECT:
		return "fp(ind)";
	case ORC_REG_SP_INDIRECT:
		return "sp(ind)";
	default:
		return "?";
	}
}

const char *orc_type_name(unsigned int type)
{
	switch (type) {
	case UNWIND_HINT_TYPE_CALL:
		return "call";
	case UNWIND_HINT_TYPE_REGS:
		return "regs";
	case UNWIND_HINT_TYPE_REGS_PARTIAL:
		return "regs (partial)";
	default:
		return "?";
	}
}

void orc_print_reg(unsigned int reg, int offset)
{
	if (reg == ORC_REG_BP_INDIRECT)
		printf("(fp%+d)", offset);
	else if (reg == ORC_REG_SP_INDIRECT)
		printf("(sp%+d)", offset);
	else if (reg == ORC_REG_UNDEFINED)
		printf("(und)");
	else
		printf("%s%+d", reg_name(reg), offset);
}
