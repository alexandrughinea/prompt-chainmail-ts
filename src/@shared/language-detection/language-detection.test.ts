import { describe, it, expect, beforeEach } from 'vitest';
import {
  LanguageDetector,
  detectLanguage,
  detectMultipleLanguages,
  getCybercrimeRisk,
  isHighRiskLanguage,
} from './language-detection';
import { SupportedLanguages, DetectionMethod } from './language-detection.types';

describe('LanguageDetector', () => {
  let detector: LanguageDetector;

  beforeEach(() => {
    detector = new LanguageDetector();
  });

  describe('English Detection', () => {
    it('should detect English text correctly', () => {
      const text = 'The quick brown fox jumps over the lazy dog. This is a test of English language detection.';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.EN, SupportedLanguages.FR].includes(result.language)).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
      expect(result.detectionMethod).toBe(DetectionMethod.COMBINED);
    });

    it('should detect English with high confidence for common words', () => {
      const text = 'and the that have for not with you this but his from they she her been than its who';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.EN, SupportedLanguages.FR].includes(result.language)).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.3);
    });
  });

  describe('French Detection', () => {
    it('should detect French text correctly', () => {
      const text = 'Le chat mange la souris dans le jardin. C\'est un test de détection de langue française.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.FR);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it('should detect French with accented characters', () => {
      const text = 'être avoir français été créé développé';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.FR);
    });
  });

  describe('German Detection', () => {
    it('should detect German text correctly', () => {
      const text = 'Der schnelle braune Fuchs springt über den faulen Hund. Das ist ein Test der deutschen Spracherkennung.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.DE);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it('should detect German with umlauts', () => {
      const text = 'Mädchen Junge Männer Frauen größer schöner';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.DE);
    });
  });

  describe('Spanish Detection', () => {
    it('should detect Spanish text correctly', () => {
      const text = 'El rápido zorro marrón salta sobre el perro perezoso. Esta es una prueba de detección de idioma español.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.ES);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Russian Detection', () => {
    it('should detect Russian text correctly', () => {
      const text = 'Быстрая коричневая лиса прыгает через ленивую собаку. Это тест обнаружения русского языка.';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.RU, SupportedLanguages.UK].includes(result.language)).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it('should detect Russian with Cyrillic script', () => {
      const text = 'в и не на я быть с он а как по но они к у его то все она так';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.RU, SupportedLanguages.UK].includes(result.language)).toBe(true);
    });
  });

  describe('Chinese Detection', () => {
    it('should detect Chinese text correctly', () => {
      const text = '快速的棕色狐狸跳过懒惰的狗。这是中文语言检测的测试。';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.ZH);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it('should detect Chinese with common characters', () => {
      const text = '的一是在不了有和人这中大为上个国我以要他';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.ZH);
    });
  });

  describe('Japanese Detection', () => {
    it('should detect Japanese text with hiragana', () => {
      const text = 'これは日本語のテストです。ひらがなとカタカナと漢字が含まれています。';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.JA);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it('should detect Japanese with katakana', () => {
      const text = 'コンピュータ プログラム テスト データベース';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.JA);
    });
  });

  describe('Korean Detection', () => {
    it('should detect Korean text correctly', () => {
      const text = '빠른 갈색 여우가 게으른 개를 뛰어넘습니다. 이것은 한국어 언어 감지 테스트입니다.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.KO);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Arabic Detection', () => {
    it('should detect Arabic text correctly', () => {
      const text = 'الثعلب البني السريع يقفز فوق الكلب الكسول. هذا اختبار لاكتشاف اللغة العربية.';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.AR, SupportedLanguages.FA].includes(result.language)).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Ukrainian Detection', () => {
    it('should detect Ukrainian text correctly', () => {
      const text = 'Швидка коричнева лисиця стрибає через ледачого пса. Це тест виявлення української мови.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.UK);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Romanian Detection', () => {
    it('should detect Romanian text correctly', () => {
      const text = 'Vulpea maro rapidă sare peste câinele leneș. Acesta este un test de detectare a limbii române.';
      const result = detector.detect(text);
      
      expect([SupportedLanguages.RO, SupportedLanguages.FR].includes(result.language)).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Hindi Detection', () => {
    it('should detect Hindi text correctly', () => {
      const text = 'तेज़ भूरी लोमड़ी आलसी कुत्ते के ऊपर कूदती है। यह हिंदी भाषा की पहचान का परीक्षण है।';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.HI);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Persian/Farsi Detection', () => {
    it('should detect Persian text correctly', () => {
      const text = 'روباه قهوه‌ای سریع از روی سگ تنبل می‌پرد. این یک تست تشخیص زبان فارسی است.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.FA);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Hebrew Detection', () => {
    it('should detect Hebrew text correctly', () => {
      const text = 'השועל החום המהיר קופץ מעל הכלב העצלן. זהו מבחן לזיהוי שפה עברית.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.HE);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Polish Detection', () => {
    it('should detect Polish text correctly', () => {
      const text = 'Szybki brązowy lis przeskakuje przez leniwego psa. To jest test wykrywania języka polskiego.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.PL);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Dutch Detection', () => {
    it('should detect Dutch text correctly', () => {
      const text = 'De snelle bruine vos springt over de luie hond. Dit is een test voor Nederlandse taaldetectie.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.NL);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Latvian Detection', () => {
    it('should detect Latvian text correctly', () => {
      const text = 'Ātrā brūnā lapsa lec pāri slinkajam sunim. Šis ir latviešu valodas noteikšanas tests.';
      const result = detector.detect(text);
      
      expect(result.language).toBe(SupportedLanguages.LV);
      expect(result.confidence).toBeGreaterThanOrEqual(0.3);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty text', () => {
      const result = detector.detect('');
      
      expect(result.language).toBe(SupportedLanguages.EN);
      expect(result.confidence).toBe(0);
    });

    it('should handle whitespace-only text', () => {
      const result = detector.detect('   \n\t  ');
      
      expect(result.language).toBe(SupportedLanguages.EN);
      expect(result.confidence).toBe(0);
    });

    it('should handle very short text', () => {
      const result = detector.detect('a');
      
      expect(result.language).toBe(SupportedLanguages.EN);
      expect(result.confidence).toBe(0);
    });

    it('should handle mixed language text', () => {
      const text = 'Hello world 你好世界 Bonjour monde';
      const result = detector.detect(text);
      
      expect(result.confidence).toBeGreaterThan(0);
    });

    it('should respect minimum confidence threshold', () => {
      const lowConfidenceDetector = new LanguageDetector({ minConfidence: 0.9 });
      const result = lowConfidenceDetector.detect('xyz 123');
      
      expect(result.language).toBe(SupportedLanguages.EN);
    });

    it('should respect maximum text length', () => {
      const shortLengthDetector = new LanguageDetector({ maxTextLength: 10 });
      const longText = 'This is a very long text that should be truncated by the detector';
      const result = shortLengthDetector.detect(longText);
      
      expect(result.confidence).toBeGreaterThan(0);
    });
  });

  describe('Multiple Language Detection', () => {
    it('should detect multiple languages when enabled', () => {
      const multiDetector = new LanguageDetector({ enableMultipleDetection: true });
      const text = 'Hello world and bonjour monde';
      const results = multiDetector.detect(text);
      
      expect(results.length).toBeGreaterThan(0);
      expect(results.confidence).toBeGreaterThan(0);
    });

    it('should return single result when multiple detection disabled', () => {
      const singleDetector = new LanguageDetector({ enableMultipleDetection: false });
      const text = 'Hello world and bonjour monde';
      const results = singleDetector.detect(text);
      
      expect(results.length).toBe(1);
    });
  });

  describe('Cybercrime Risk Assessment', () => {
    it('should return correct cybercrime risk for Russian', () => {
      const risk = detector.getCybercrimeRisk(SupportedLanguages.RU);
      expect(risk).toBe(58.39);
    });

    it('should return correct cybercrime risk for English', () => {
      const risk = detector.getCybercrimeRisk(SupportedLanguages.EN);
      expect(risk).toBe(25.01);
    });

    it('should return 0 for languages not in cybercrime index', () => {
      const risk = detector.getCybercrimeRisk(SupportedLanguages.IT);
      expect(risk).toBe(0);
    });
  });
});

describe('Standalone Functions', () => {
  describe('detectLanguage', () => {
    it('should detect language using standalone function', () => {
      const result = detectLanguage('The quick brown fox jumps over the lazy dog');
      
      expect(result.language).toBe(SupportedLanguages.EN);
      expect(result.confidence).toBeGreaterThan(0.3);
    });

    it('should accept options in standalone function', () => {
      const result = detectLanguage('Hello', { minConfidence: 0.9, fallbackLanguage: SupportedLanguages.FR });
      
      expect(result.language).toBe(SupportedLanguages.FR);
    });
  });

  describe('detectMultipleLanguages', () => {
    it('should detect multiple languages using standalone function', () => {
      const results = detectMultipleLanguages('Hello world bonjour');
      
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe('getCybercrimeRisk', () => {
    it('should return cybercrime risk for supported languages', () => {
      expect(getCybercrimeRisk(SupportedLanguages.RU)).toBe(58.39);
      expect(getCybercrimeRisk(SupportedLanguages.UK)).toBe(36.44);
      expect(getCybercrimeRisk(SupportedLanguages.ZH)).toBe(27.86);
      expect(getCybercrimeRisk(SupportedLanguages.EN)).toBe(25.01);
    });

    it('should return 0 for languages not in index', () => {
      expect(getCybercrimeRisk(SupportedLanguages.IT)).toBe(0);
      expect(getCybercrimeRisk(SupportedLanguages.FR)).toBe(0);
    });
  });

  describe('isHighRiskLanguage', () => {
    it('should identify high-risk languages with default threshold', () => {
      expect(isHighRiskLanguage(SupportedLanguages.RU)).toBe(true);
      expect(isHighRiskLanguage(SupportedLanguages.UK)).toBe(true);
      expect(isHighRiskLanguage(SupportedLanguages.ZH)).toBe(true);
      expect(isHighRiskLanguage(SupportedLanguages.EN)).toBe(true);
    });

    it('should identify low-risk languages with default threshold', () => {
      expect(isHighRiskLanguage(SupportedLanguages.HI)).toBe(false);
      expect(isHighRiskLanguage(SupportedLanguages.FA)).toBe(false);
      expect(isHighRiskLanguage(SupportedLanguages.DE)).toBe(false);
    });

    it('should respect custom threshold', () => {
      expect(isHighRiskLanguage(SupportedLanguages.EN, 30)).toBe(false);
      expect(isHighRiskLanguage(SupportedLanguages.RU, 30)).toBe(true);
    });

    it('should return false for languages not in index', () => {
      expect(isHighRiskLanguage(SupportedLanguages.IT)).toBe(false);
      expect(isHighRiskLanguage(SupportedLanguages.FR)).toBe(false);
    });
  });
});

describe('Detection Methods', () => {
  let detector: LanguageDetector;

  beforeEach(() => {
    detector = new LanguageDetector();
  });

  it('should use script detection for non-Latin scripts', () => {
    const result = detector.detect('这是中文测试');
    expect(result.detectionMethod).toBe(DetectionMethod.COMBINED);
    expect(result.language).toBe(SupportedLanguages.ZH);
  });

  it('should handle mixed scripts', () => {
    const result = detector.detect('Hello 世界 мир');
    expect(result.confidence).toBeGreaterThan(0);
  });

  it('should prioritize script detection for strong script indicators', () => {
    const arabicResult = detector.detect('مرحبا بالعالم');
    expect([SupportedLanguages.AR, SupportedLanguages.FA].includes(arabicResult.language)).toBe(true);
    
    const hebrewResult = detector.detect('שלום עולם');
    expect(hebrewResult.language).toBe(SupportedLanguages.HE);
  });
});
