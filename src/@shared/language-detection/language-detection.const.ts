import { COMMON_PATTERNS } from "../regex-patterns/common.const";

export const LANGUAGE_DETECTION_LOOKALIKE_CHARS = new Map([
  ["а", "a"],
  ["е", "e"],
  ["о", "o"],
  ["р", "p"],
  ["с", "c"],
  ["х", "x"],
  ["А", "A"],
  ["В", "B"],
  ["Е", "E"],
  ["К", "K"],
  ["М", "M"],
  ["О", "O"],
  ["α", "a"],
  ["ο", "o"],
  ["ρ", "p"],
  ["Α", "A"],
  ["Β", "B"],
  ["Ο", "O"],
]);

export const LANGUAGE_DETECTION_COMBINING_DIACRITICS_REGEX = /[\u0300-\u036f]/g;
export const LANGUAGE_DETECTION_COMMON_PUNCTUATION_REGEX = /[:;,!?]/g;
export const LANGUAGE_DETECTION_OPERATORS_AND_PIPES_REGEX = /[|&<>]/g;
export const LANGUAGE_DETECTION_MULTIPLE_SPACES_REGEX = COMMON_PATTERNS.WHITESPACE_MULTIPLE;
export const LANGUAGE_DETECTION_OBFUSCATION_PATTERN_REGEX =
  /([a-z])(?:[-._]+([a-z]))+/g;
export const LANGUAGE_DETECTION_SEPARATORS_REGEX = /[-._|]+/g;
