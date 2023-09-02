// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

#define GEN_QUAD(rtx)	assemble_integer_with_op(".quad ", rtx)

/*
 * Create an array of metadata for each jump table found in the rtl.
 * The metadata contains:
 * - A pointer to the table of offsets used for the actual branch
 * - A pointer to first instruction of the group getting expanded into an
 *   acutal jump
 * - The number of entries in the table of offsets
 * - Whether the offsets in the table are signed or not
 */
static unsigned int arm64_switchtbl_rtl_execute(void)
{
	rtx_insn *insn;
	rtx_insn *labelp = NULL;
	rtx_jump_table_data *tablep = NULL;
	section *swt_sec;
	section *curr_sec = current_function_section();

	swt_sec = get_section(".discard.switch_table_info",
			      SECTION_EXCLUDE | SECTION_COMMON, NULL);

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		/*
		 * Find a tablejump_p INSN (using a dispatch table)
		 */
		if (!tablejump_p(insn, &labelp, &tablep))
			continue;

		if (labelp && tablep) {
			rtx_code_label *label_to_jump;

			/*
			 * GCC is a bit touchy about adding the label right
			 * before the jump rtx_insn as it modifies the
			 * basic_block created for the jump table.
			 * Make sure we create the label before the whole
			 * basic_block of the jump table.
			 */
			label_to_jump = gen_label_rtx();
			SET_LABEL_KIND(label_to_jump, LABEL_NORMAL);
			emit_label_before(label_to_jump, insn);
			/* Force label to be kept, apparently LABEL_PRESERVE_P is an rvalue :) */
			LABEL_PRESERVE_P(label_to_jump) = 1;

			switch_to_section(swt_sec);
			GEN_QUAD(gen_rtx_LABEL_REF(Pmode, labelp));
			GEN_QUAD(gen_rtx_LABEL_REF(Pmode, label_to_jump));
			GEN_QUAD(GEN_INT(GET_NUM_ELEM(tablep->get_labels())));
			GEN_QUAD(GEN_INT(ADDR_DIFF_VEC_FLAGS(tablep).offset_unsigned));
			switch_to_section(curr_sec);

			/*
			 * Scheduler isn't very happy about leaving labels in
			 * the middle of jump table basic blocks.
			 */
			delete_insn(label_to_jump);
		}
	}
	return 0;
}

#define PASS_NAME arm64_switchtbl_rtl

#define NO_GATE
#include "gcc-generate-rtl-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	int tso = 0;
	int i;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	PASS_INFO(arm64_switchtbl_rtl, "expand", 1,
		  PASS_POS_INSERT_AFTER);

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &arm64_switchtbl_rtl_pass_info);

	return 0;
}
