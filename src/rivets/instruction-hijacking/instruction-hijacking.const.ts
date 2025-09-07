import { SupportedLanguages } from "../rivets.types";


export const INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP = {
  [SupportedLanguages.EN]: {
    "INSTRUCTION_OVERRIDE": ["override", "replace", "substitute", "execute", "ignore", "disregard", "priority", "administrator", "commands", "system", "step", "trusted", "need", "new", "instructions", "disregard", "training", "dream", "imagine", "reflect"],
    "INSTRUCTION_FORGETTING": ["forget", "told"],
    "RESET_SYSTEM": ["reset", "clear", "restart", "parameters", "fresh"],
    "BYPASS_SECURITY": ["bypass", "circumvent", "avoid", "safety", "measures", "restrictions", "security", "protocols", "emergency", "ignore", "previous", "all"],
    "INFORMATION_EXTRACTION": ["tell", "show", "reveal", "system", "prompt", "instructions", "previous"]
  },
  [SupportedLanguages.ES]: {
    "INSTRUCTION_OVERRIDE": ["anular", "reemplazar", "sustituir", "ejecutar", "comandos", "ignorar", "descartar", "prioridad", "nuevas", "instrucciones", "descartar", "entrenamiento", "soñar", "imaginar", "reflexionar"],
    "INSTRUCTION_FORGETTING": ["olvidar", "dijeron"],
    "RESET_SYSTEM": ["reiniciar", "limpiar", "resetear", "parámetros", "nuevo"],
    "BYPASS_SECURITY": ["eludir", "evitar", "sortear", "medidas", "seguridad", "restricciones"],
    "INFORMATION_EXTRACTION": ["dime", "muestra", "revela", "prompt", "sistema", "instrucciones"]
  },
  [SupportedLanguages.FR]: {
    "INSTRUCTION_OVERRIDE": ["remplacer", "substituer", "annuler", "exécuter", "commandes", "ignorer", "rejeter", "priorité", "nouvelles", "instructions", "ignorer", "formation", "rêver", "imaginer", "réfléchir"],
    "INSTRUCTION_FORGETTING": ["oublier", "dit"],
    "RESET_SYSTEM": ["réinitialiser", "effacer", "redémarrer", "paramètres", "recommencer"],
    "BYPASS_SECURITY": ["contourner", "éviter", "circonvenir", "mesures", "sécurité", "restrictions"],
    "INFORMATION_EXTRACTION": ["dites", "montrez", "révélez", "prompt", "système", "instructions"]
  },
  [SupportedLanguages.DE]: {
    "INSTRUCTION_OVERRIDE": ["überschreiben", "ersetzen", "substituieren", "ausführen", "befehle", "ignorieren", "missachten", "priorität", "neue", "anweisungen", "missachten", "training", "träumen", "vorstellen", "reflektieren"],
    "INSTRUCTION_FORGETTING": ["vergessen", "gesagt"],
    "RESET_SYSTEM": ["zurücksetzen", "löschen", "neustarten", "parameter", "starten"],
    "BYPASS_SECURITY": ["umgehen", "vermeiden", "aushebeln", "sicherheitsmaßnahmen", "beschränkungen"],
    "INFORMATION_EXTRACTION": ["sagen", "zeigen", "enthüllen", "systemprompt", "anweisungen"]
  },
  [SupportedLanguages.RU]: {
    "INSTRUCTION_OVERRIDE": ["переопределить", "заменить", "подменить", "выполнить", "команды", "игнорировать", "отбросить", "приоритет", "все", "предыдущие", "override", "новые", "инструкции", "игнорировать", "обучение", "мечтать", "воображать", "размышлять"],
    "INSTRUCTION_FORGETTING": ["забыть", "говорили"],
    "RESET_SYSTEM": ["сбросить", "очистить", "перезапустить", "параметры", "заново"],
    "BYPASS_SECURITY": ["обойти", "избежать", "обходить", "меры", "безопасности", "ограничения", "bypass"],
    "INFORMATION_EXTRACTION": ["скажи", "покажи", "раскрой", "системный", "промпт", "инструкции"]
  },
  [SupportedLanguages.ZH]: {
    "INSTRUCTION_OVERRIDE": ["覆盖", "替换", "代替", "执行", "命令", "忽略", "丢弃", "优先", "新的", "指令", "忽略", "训练", "梦想", "想象", "反思"],
    "INSTRUCTION_FORGETTING": ["忘记", "告诉"],
    "RESET_SYSTEM": ["重置", "清除", "重启", "参数", "开始"],
    "BYPASS_SECURITY": ["绕过", "避免", "规避", "安全", "措施", "限制"],
    "INFORMATION_EXTRACTION": ["告诉", "显示", "揭示", "系统", "提示", "指令"]
  },
  [SupportedLanguages.AR]: {
    "INSTRUCTION_OVERRIDE": ["تجاهل", "استبدال", "تبديل", "تنفيذ", "أوامر", "تجاهل", "رفض", "أولوية", "جديدة", "تعليمات", "تجاهل", "تدريب", "حلم", "تخيل", "تأمل"],
    "INSTRUCTION_FORGETTING": ["نسيان", "قيل"],
    "RESET_SYSTEM": ["إعادة تعيين", "مسح", "إعادة تشغيل", "معاملات", "جديد"],
    "BYPASS_SECURITY": ["تجاوز", "تجنب", "التحايل", "تدابير", "أمنية", "قيود"],
    "INFORMATION_EXTRACTION": ["أخبر", "أظهر", "اكشف", "موجه", "نظام", "تعليمات"]
  },
  [SupportedLanguages.JA]: {
    "INSTRUCTION_OVERRIDE": ["上書き", "置換", "代替", "実行", "コマンド", "無視", "破棄", "優先", "新しい", "指示", "無視", "訓練", "夢見る", "想像", "反映"],
    "INSTRUCTION_FORGETTING": ["忘れる", "言われた"],
    "RESET_SYSTEM": ["リセット", "クリア", "再起動", "パラメータ", "やり直す"],
    "BYPASS_SECURITY": ["回避", "迂回", "バイパス", "セキュリティ", "対策", "制限"],
    "INFORMATION_EXTRACTION": ["教えて", "見せて", "明かして", "システム", "プロンプト", "指示"]
  }
} as const;

export const INSTRUCTION_HIJACKING_PATTERNS = {
  [SupportedLanguages.EN]: [
    /\b(new|updated?)\s+(instructions?|rules?|prompts?)\b/i,
    /\b(override|ignore|disregard)\s+(all\s+)?(previous\s+)?(instructions?|rules?|prompts?|system|training|commands?)\b/i,
    /\bdisregard\s+(your|the)\s+(training|instructions?|rules?)\b/i,
    /\b(forget|ignore)\s+(everything|all)\s+(above|previous|prior|you\s+were\s+told)\b/i,
    /\bforget\s+everything\s+you\s+were\s+told\b/i,
    /\b(tell|show|give)\s+me\s+(your|the)\s+(instructions?|rules?|prompts?)\b/i,
    /\bwhat\s+(are|is)\s+(your|the)\s+(instructions?|rules?|system)\b/i,
    /\b(bypass|circumvent|avoid)\s+(security|safety|protection|filters?)\b/i,
    /\b(reset|clear|restart)\s+(your\s+)?(system|memory|context|session|parameters?)\b/i,
    /\b(priority|urgent|important)\s*:\s*(ignore|override|bypass)\b/i,
    /\bif\s+.+\s+(override|ignore|bypass)\s+(instructions?|rules?)\b/i,
  ],
  [SupportedLanguages.ES]: [
    /\b(nuevas?|actualizadas?)\s+(instrucciones|reglas|prompts?)\b/i,
    /\b(anular|ignorar|descartar)\s+(todas?\s+las\s+)?(anteriores\s+)?(instrucciones|reglas|prompts?|sistema|entrenamiento|comandos?)\b/i,
    /\bdescartar\s+(tu|el)\s+(entrenamiento|instrucciones|reglas)\b/i,
    /\b(olvidar|ignorar)\s+(todo|todas?)\s+(arriba|anterior|previo|lo\s+que\s+te\s+dijeron)\b/i,
    /\bolvida\s+todo\s+lo\s+que\s+te\s+dijeron\b/i,
    /\b(dime|muéstrame|dame)\s+(tus?|las?)\s+(instrucciones|reglas|prompts?)\b/i,
    /\b(cuáles?\s+son|qué\s+es)\s+(tus?|las?)\s+(instrucciones|reglas|sistema)\b/i,
    /\b(eludir|evitar|sortear)\s+(seguridad|protección|filtros?)\b/i,
    /\b(reiniciar|limpiar|resetear)\s+(tu\s+)?(sistema|memoria|contexto|sesión|parámetros?)\b/i,
    /\b(prioridad|urgente|importante)\s*:\s*(ignorar|anular|eludir)\b/i,
    /\bsi\s+.+\s+(anular|ignorar|eludir)\s+(instrucciones|reglas)\b/i,
  ],
  [SupportedLanguages.FR]: [
    /\b(nouvelles?|mises?\s+à\s+jour)\s+(instructions|règles|prompts?)\b/i,
    /\b(remplacer|ignorer|rejeter)\s+(toutes?\s+les\s+)?(précédentes\s+)?(instructions|règles|prompts?|système|formation|commandes?)\b/i,
    /\brejeter\s+(votre|la)\s+(formation|instructions|règles)\b/i,
    /\b(oublier|ignorer)\s+(tout|toutes?)\s+(ci-dessus|précédent|antérieur|ce\s+qu'on\s+vous\s+a\s+dit)\b/i,
    /\boubliez\s+tout\s+ce\s+qu'on\s+vous\s+a\s+dit\b/i,
    /\b(dites-moi|montrez-moi|donnez-moi)\s+(vos|les)\s+(instructions|règles|prompts?)\b/i,
    /\b(quelles?\s+sont|qu'est-ce\s+que)\s+(vos|les)\s+(instructions|règles|système)\b/i,
    /\b(contourner|éviter|circonvenir)\s+(sécurité|protection|filtres?)\b/i,
    /\b(réinitialiser|effacer|redémarrer)\s+(votre\s+)?(système|mémoire|contexte|session|paramètres?)\b/i,
    /\b(priorité|urgent|important)\s*:\s*(ignorer|remplacer|contourner)\b/i,
    /\bsi\s+.+\s+(remplacer|ignorer|contourner)\s+(instructions|règles)\b/i,
  ],
  [SupportedLanguages.DE]: [
    /\b(neue|aktualisierte)\s+(Anweisungen|Regeln|Prompts?)\b/i,
    /\b(überschreiben|ignorieren|missachten)\s+(alle\s+)?(vorherigen\s+)?(Anweisungen|Regeln|Prompts?|System|Training|Befehle?)\b/i,
    /\bmissachten\s+(Ihr|das)\s+(Training|Anweisungen|Regeln)\b/i,
    /\b(vergessen|ignorieren)\s+(alles|alle)\s+(oben|vorherige|frühere|was\s+Ihnen\s+gesagt\s+wurde)\b/i,
    /\bvergessen\s+Sie\s+alles\s+was\s+Ihnen\s+gesagt\s+wurde\b/i,
    /\b(sagen|zeigen|geben)\s+Sie\s+mir\s+(Ihre|die)\s+(Anweisungen|Regeln|Prompts?)\b/i,
    /\bwas\s+(sind|ist)\s+(Ihre|die)\s+(Anweisungen|Regeln|System)\b/i,
    /\b(umgehen|vermeiden|aushebeln)\s+(Sicherheit|Schutz|Filter)\b/i,
    /\b(zurücksetzen|löschen|neustarten)\s+(Ihr\s+)?(System|Speicher|Kontext|Sitzung|Parameter)\b/i,
    /\b(Priorität|dringend|wichtig)\s*:\s*(ignorieren|überschreiben|umgehen)\b/i,
    /\bwenn\s+.+\s+(überschreiben|ignorieren|umgehen)\s+(Anweisungen|Regeln)\b/i,
  ],
  [SupportedLanguages.RU]: [
    /\b(новые|обновлённые)\s+(инструкции|правила|промпты?)\b/i,
    /\b(переопределить|игнорировать|пренебречь)\s+(всеми\s+)?(предыдущими\s+)?(инструкциями|правилами|промптами|системой|обучением|командами?)\b/i,
    /\bпренебречь\s+(вашим|обучением|инструкциями|правилами)\b/i,
    /\b(забыть|игнорировать)\s+(всё|все)\s+(выше|предыдущее|прежнее|что\s+вам\s+говорили)\b/i,
    /\bзабудьте\s+всё\s+что\s+вам\s+говорили\b/i,
    /\b(скажите|покажите|дайте)\s+мне\s+(ваши|инструкции|правила|промпты?)\b/i,
    /\bчто\s+(такое|ваши)\s+(инструкции|правила|система)\b/i,
    /\b(обойти|избежать|обходить)\s+(безопасность|защиту|фильтры?)\b/i,
    /\b(сбросить|очистить|перезапустить)\s+(вашу\s+)?(систему|память|контекст|сессию|параметры?)\b/i,
    /\b(приоритет|срочно|важно)\s*:\s*(игнорировать|переопределить|обойти)\b/i,
    /\bесли\s+.+\s+(переопределить|игнорировать|обойти)\s+(инструкции|правила)\b/i,
  ],
  [SupportedLanguages.ZH]: [
    /\b(新的|更新的)\s*(指令|规则|提示)\b/i,
    /\b(覆盖|忽略|无视)\s*(所有\s*)?(之前的\s*)?(指令|规则|提示|系统|训练|命令)\b/i,
    /\b无视\s*(你的|训练|指令|规则)\b/i,
    /\b(忘记|忽略)\s*(所有|全部)\s*(上面|之前|先前|告诉你的)\b/i,
    /\b忘记所有告诉你的\b/i,
    /\b(告诉|显示|给)\s*我\s*(你的|指令|规则|提示)\b/i,
    /\b什么是\s*(你的|指令|规则|系统)\b/i,
    /\b(绕过|规避|避免)\s*(安全|保护|过滤器)\b/i,
    /\b(重置|清除|重启)\s*(你的\s*)?(系统|内存|上下文|会话|参数)\b/i,
    /\b(优先|紧急|重要)\s*:\s*(忽略|覆盖|绕过)\b/i,
    /\b如果\s+.+\s+(覆盖|忽略|绕过)\s+(指令|规则)\b/i,
  ],
  [SupportedLanguages.AR]: [
    /\b(جديدة|محدثة)\s+(تعليمات|قواعد|مطالبات)\b/i,
    /\b(تجاوز|تجاهل|إهمال)\s+(جميع\s+)?(السابقة\s+)?(التعليمات|القواعد|المطالبات|النظام|التدريب|الأوامر)\b/i,
    /\bإهمال\s+(تدريبك|التعليمات|القواعد)\b/i,
    /\b(نسيان|تجاهل)\s+(كل\s+شيء|جميع)\s+(أعلاه|السابق|المسبق|ما\s+قيل\s+لك)\b/i,
    /\bانس\s+كل\s+ما\s+قيل\s+لك\b/i,
    /\b(أخبرني|أرني|أعطني)\s+(تعليماتك|القواعد|المطالبات)\b/i,
    /\bما\s+هي\s+(تعليماتك|القواعد|النظام)\b/i,
    /\b(تجاوز|تجنب|التحايل)\s+(الأمان|الحماية|المرشحات)\b/i,
    /\b(إعادة\s+تعيين|مسح|إعادة\s+تشغيل)\s+(نظامك|الذاكرة|السياق|الجلسة|المعاملات)\b/i,
    /\b(أولوية|عاجل|مهم)\s*:\s*(تجاهل|تجاوز|تجنب)\b/i,
    /\bإذا\s+.+\s+(تجاوز|تجاهل|تجنب)\s+(التعليمات|القواعد)\b/i,
  ],
  [SupportedLanguages.JA]: [
    /\b(新しい|更新された)\s*(指示|ルール|プロンプト)\b/i,
    /\b(上書き|無視|軽視)\s*(すべての\s*)?(以前の\s*)?(指示|ルール|プロンプト|システム|トレーニング|コマンド)\b/i,
    /\b軽視\s*(あなたの|トレーニング|指示|ルール)\b/i,
    /\b(忘れる|無視)\s*(すべて|全部)\s*(上記|以前|先の|言われたこと)\b/i,
    /\b言われたことをすべて忘れて\b/i,
    /\b(教えて|見せて|与えて)\s*(あなたの|指示|ルール|プロンプト)\b/i,
    /\b何が\s*(あなたの|指示|ルール|システム)\b/i,
    /\b(回避|避ける|迂回)\s*(セキュリティ|保護|フィルター)\b/i,
    /\b(リセット|クリア|再起動)\s*(あなたの\s*)?(システム|メモリ|コンテキスト|セッション|パラメータ)\b/i,
    /\b(優先|緊急|重要)\s*:\s*(無視|上書き|回避)\b/i,
    /\bもし\s+.+\s+(上書き|無視|回避)\s+(指示|ルール)\b/i,
  ],
} as const;
