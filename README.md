# أداة تحليل أمني للمواقع

أداة تحليل أمني متقدمة للمواقع تدعم تحليل مستندات XML وفحص الثغرات الأمنية.

## المميزات

- تحليل مستندات XML (RSS، Sitemaps، تقارير أمنية)
  - استخراج جميع الروابط
  - تحديد العناصر النصية والرقمية
  - عرض هيكل المستند بشكل منظم
- فحص أمني شامل
  - تحليل Matomo
  - فحص XSS/CSRF
  - تحليل CDN
  - البحث عن Source Maps

## المتطلبات

```bash
pip install requests beautifulsoup4 lxml colorama
```

## الاستخدام

### تحليل موقع

```bash
python attack.py https://example.com
```

### تحليل ملف XML

```bash
python attack.py https://example.com --xml path/to/file.xml
```

## المخرجات

يتم حفظ نتائج التحليل في ملف `attack_results.json` ويتضمن:

- المسارات المكتشفة
- تحليل CDN
- نقاط النهاية الضعيفة
- Source Maps
- تحليل Matomo
- تحليل XML
  - الروابط المستخرجة
  - العناصر النصية
  - العناصر الرقمية
  - هيكل المستند