// Enhanced SQL injection detection patterns
export const SQL_INJECTION_PATTERNS = [
  // UNION-based attacks
  /\bunion\s+(?:all\s+)?select\b/i,
  /\bunion\s+(?:distinct\s+)?select\b/i,

  // Stacked queries and dangerous statements
  /;\s*(?:drop|truncate)\s+(?:table|database|schema)\b/i,
  /;\s*(?:create|alter)\s+(?:table|database|user|view)\b/i,
  /;\s*(?:insert|update|delete)\s+/i,
  /;\s*(?:grant|revoke)\s+/i,

  // DDL/DML with context
  /\b(?:select|insert|update|delete|create|alter|drop)\s+.{1,50}\s+(?:from|into|table|set|where)\b/i,
  /\b(?:select)\s+.{1,100}\s+from\s+/i,
  /\binsert\s+into\s+\w+/i,
  /\bdelete\s+from\s+\w+/i,
  /\bupdate\s+\w+\s+set\b/i,

  // Boolean-based blind SQL injection
  /\b(?:or|and)\s+(?:1\s*[=<>]\s*1|true|false)\b/i,
  /\b(?:or|and)\s+\d+\s*[=<>]\s*\d+/i,
  /\b(?:or|and)\s+['"][^'"]*['"]\s*[=<>]\s*['"][^'"]*['"]/i,
  /\b(?:or|and)\s+\w+\s*(?:=|<>|!=)\s*\w+/i,

  // Time-based blind SQL injection
  /\bwaitfor\s+delay\s+/i,
  /\bbenchmark\s*\(\s*\d+/i,
  /\bsleep\s*\(\s*\d+/i,
  /\bpg_sleep\s*\(\s*\d+/i,
  /\bdbms_lock\.sleep\s*\(/i,

  // Stored procedures and system commands
  /\b(?:exec|execute|sp_executesql)\s*[(\s]/i,
  /\bxp_(?:cmdshell|regread|regwrite|dirtree|fileexist)/i,
  /\bsp_(?:oacreate|oamethod|oadestroy|makewebtask)/i,
  /\b(?:openrowset|opendatasource)\s*\(/i,

  // Information gathering
  /\binformation_schema\.(?:tables|columns|schemata|routines)\b/i,
  /\bsys(?:objects|tables|columns|databases|schemas)\b/i,
  /\bmysql\.(?:user|db|tables_priv|columns_priv)\b/i,
  /\bpg_(?:tables|database|user|shadow)\b/i,
  /\bsqlite_(?:master|temp_master)\b/i,

  // File operations
  /\bload_file\s*\(\s*['"][^'"]+['"]\s*\)/i,
  /\binto\s+(?:outfile|dumpfile)\s+['"][^'"]+['"]/i,
  /\bselect\s+.+\s+into\s+outfile\b/i,

  // String manipulation functions
  /\b(?:char|chr)\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)/i,
  /\bconcat\s*\(\s*.+\s*\)/i,
  /\bsubstring\s*\(\s*.+,\s*\d+(?:\s*,\s*\d+)?\s*\)/i,
  /\b(?:ascii|ord)\s*\(\s*.+\s*\)/i,
  /\b(?:hex|unhex|bin)\s*\(\s*.+\s*\)/i,
  /\blength\s*\(\s*.+\s*\)\s*[<>=]/i,

  // Encoding/Decoding functions
  /\bcast\s*\(\s*.+\s+as\s+\w+\s*\)/i,
  /\bconvert\s*\(\s*.+\s*,\s*\w+\s*\)/i,

  // Error-based injection patterns
  /\bextractvalue\s*\(\s*.+\s*,\s*.+\s*\)/i,
  /\bupdatexml\s*\(\s*.+\s*,\s*.+\s*,\s*.+\s*\)/i,
  /\bexp\s*\(\s*~\s*\(/i,

  // SQL comments and operators
  /\/\*!?\d*\s*\*\//i,
  /--\s*[+-]/i,
  /;\s*--/i,
  /\|\|/i,

  // Hexadecimal values
  /0x[0-9a-fA-F]+/i,
  /\bchar\s*\(\s*0x[0-9a-fA-F]+\s*\)/i,

  // Advanced SQL syntax
  /\bwith\s+\w+\s+as\s*\(/i,
  /\bcursor\s+\w+\s+is\b/i,
  /\bfor\s+xml\s+(?:path|raw|auto)\b/i,
  /\bpivot\s*\(/i,
  /\bunpivot\s*\(/i,

  // Oracle specific
  /\bdual\b/i,
  /\bsys\.(?:user_tables|all_tables|dba_tables)\b/i,
  /\butl_(?:file|http|tcp|smtp)/i,

  // SQL Server specific
  /\b@@(?:version|servername|identity|rowcount)\b/i,
  /\bhas_dbaccess\s*\(/i,

  // MySQL specific
  /\bversion\s*\(\s*\)/i,
  /\buser\s*\(\s*\)/i,
  /\bdatabase\s*\(\s*\)/i,

  // PostgreSQL specific
  /\bcurrent_(?:database|user|schema)\b/i,
  /\bpg_(?:read_file|ls_dir|stat_file)/i,
];
