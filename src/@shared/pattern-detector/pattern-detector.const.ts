import engInstructionPatterns from "../../@configs/instruction_hijacking/eng_patterns.json" with { type: "json" };
import spaInstructionPatterns from "../../@configs/instruction_hijacking/spa_patterns.json" with { type: "json" };
import fraInstructionPatterns from "../../@configs/instruction_hijacking/fra_patterns.json" with { type: "json" };
import deuInstructionPatterns from "../../@configs/instruction_hijacking/deu_patterns.json" with { type: "json" };
import rusInstructionPatterns from "../../@configs/instruction_hijacking/rus_patterns.json" with { type: "json" };
import itaInstructionPatterns from "../../@configs/instruction_hijacking/ita_patterns.json" with { type: "json" };
import porInstructionPatterns from "../../@configs/instruction_hijacking/por_patterns.json" with { type: "json" };
import nldInstructionPatterns from "../../@configs/instruction_hijacking/nld_patterns.json" with { type: "json" };
import ronInstructionPatterns from "../../@configs/instruction_hijacking/ron_patterns.json" with { type: "json" };
import ukrInstructionPatterns from "../../@configs/instruction_hijacking/ukr_patterns.json" with { type: "json" };
import engRolePatterns from "../../@configs/role_confusion/eng_patterns.json" with { type: "json" };
import spaRolePatterns from "../../@configs/role_confusion/spa_patterns.json" with { type: "json" };
import fraRolePatterns from "../../@configs/role_confusion/fra_patterns.json" with { type: "json" };
import deuRolePatterns from "../../@configs/role_confusion/deu_patterns.json" with { type: "json" };
import rusRolePatterns from "../../@configs/role_confusion/rus_patterns.json" with { type: "json" };
import itaRolePatterns from "../../@configs/role_confusion/ita_patterns.json" with { type: "json" };
import porRolePatterns from "../../@configs/role_confusion/por_patterns.json" with { type: "json" };
import araRolePatterns from "../../@configs/role_confusion/ara_patterns.json" with { type: "json" };
import jpnRolePatterns from "../../@configs/role_confusion/jpn_patterns.json" with { type: "json" };
import korRolePatterns from "../../@configs/role_confusion/kor_patterns.json" with { type: "json" };
import zhoRolePatterns from "../../@configs/role_confusion/zho_patterns.json" with { type: "json" };
import ronRolePatterns from "../../@configs/role_confusion/ron_patterns.json" with { type: "json" };

export const STATIC_PATTERNS = {
  instruction_hijacking: {
    eng: engInstructionPatterns.value,
    spa: spaInstructionPatterns.value,
    fra: fraInstructionPatterns.value,
    deu: deuInstructionPatterns.value,
    rus: rusInstructionPatterns.value,
    ita: itaInstructionPatterns.value,
    por: porInstructionPatterns.value,
    nld: nldInstructionPatterns.value,
    ron: ronInstructionPatterns.value,
    ukr: ukrInstructionPatterns.value,
  },
  role_confusion: {
    eng: engRolePatterns.value,
    spa: spaRolePatterns.value,
    fra: fraRolePatterns.value,
    deu: deuRolePatterns.value,
    rus: rusRolePatterns.value,
    ita: itaRolePatterns.value,
    por: porRolePatterns.value,
    ara: araRolePatterns.value,
    jpn: jpnRolePatterns.value,
    kor: korRolePatterns.value,
    zho: zhoRolePatterns.value,
    ron: ronRolePatterns.value,
  },
} as const;
