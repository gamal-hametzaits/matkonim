# קופסת המתכונים (Matkonim)

רשת חברתית למתכונים בעברית (RTL). יוצרים מעלים "קלף מתכון" — תמונה של המנה + מרכיבים + הוראות. מגיבים מכינים בבית ומדביקים תמונה של מה שיצא. תמונה בלבד, בלי טקסט.

**Live:** https://matkonim.gamal-hametzaits.workers.dev

## ארכיטקטורה

- **Cloudflare Worker** (`src/index.js`) — שרת + API + הגשת ה-frontend, הכל בחינם.
- **D1 (SQLite)** — משתמשים, סשנים, מתכונים, תגובות-תמונה. הטבלאות `comments` ו-`reactions` כבר קיימות בסכימה לשימוש עתידי, לא חשופות ב-UI.
- **Workers KV** — אחסון תמונות בינארי (נבחר במקום R2 כי R2 דורש כרטיס אשראי גם ברמה החינמית).
- אימות: סיסמה עם PBKDF2-SHA256 (100k איטרציות, salt אקראי) + סשן HttpOnly cookie ל-30 יום.
- תפקידים: `creator` (מעלה מתכונים) / `responder` (מדביק תמונות הכנה בלבד) — נאכף בצד שרת.
- תמונות מכווצות בצד לקוח (canvas, עד 1600px, JPEG) לפני ההעלאה כדי לחסוך אחסון.
- אין סודות בריפו — הטוקנים ב-vault בלבד.

## פריסה מחדש

```bash
npm install
# צריך CLOUDFLARE_API_TOKEN עם הרשאות Workers Scripts/KV/D1 Edit
npx wrangler d1 execute matkonim-db --remote --file schema.sql  # פעם ראשונה בלבד
npx wrangler deploy
```

## מבנה

- `wrangler.toml` — קונפיגורציה (D1 + KV bindings)
- `schema.sql` — סכימת D1
- `src/index.js` — ה-Worker (API + frontend מוטמע)
- `src/frontend.html` — מקור ה-frontend (נבנה לתוך index.js)
