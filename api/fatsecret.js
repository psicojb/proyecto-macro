const crypto = require('crypto');

function rfc3986(str) {
  return encodeURIComponent(String(str)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const query = req.query.q;
  if (!query) return res.status(200).json({ results: [] });

  const consumerKey = process.env.FATSECRET_CLIENT_ID;
  const consumerSecret = process.env.FATSECRET_CLIENT_SECRET;

  if (!consumerKey || !consumerSecret) {
    return res.status(500).json({ error: 'Faltan credenciales de FatSecret en Vercel' });
  }

  try {
    const httpMethod = 'GET';
    const baseUrl = 'https://platform.fatsecret.com/rest/server.api';

    const params = {
      format: 'json',
      language: 'es',
      max_results: '50',
      method: 'foods.search',
      oauth_consumer_key: consumerKey.trim(),
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
      region: 'MX',
      search_expression: query.trim()
    };

    const sortedKeys = Object.keys(params).sort();
    const paramString = sortedKeys.map(k => `${rfc3986(k)}=${rfc3986(params[k])}`).join('&');
    const signatureBaseString = `${httpMethod}&${rfc3986(baseUrl)}&${rfc3986(paramString)}`;
    const signingKey = `${rfc3986(consumerSecret.trim())}&`;
    const signature = crypto.createHmac('sha1', signingKey).update(signatureBaseString).digest('base64');
    const requestUrl = `${baseUrl}?${paramString}&oauth_signature=${rfc3986(signature)}`;

    const apiRes = await fetch(requestUrl);
    const searchResponse = await apiRes.json().catch(() => ({}));

    if (searchResponse.error) {
      throw new Error(`FatSecret Error (${searchResponse.error.code}): ${searchResponse.error.message}`);
    }

    const rawFoods = searchResponse.foods?.food;
    const allFoods = Array.isArray(rawFoods) ? rawFoods : (rawFoods ? [rawFoods] : []);

    // Palabras irrelevantes que no deben usarse solas como filtro (de, la, con...)
    const cleanQueryWords = query.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .split(/\s+/)
      .filter(w => w.length > 2 && !['del', 'las', 'los', 'con', 'para', 'por'].includes(w));

    const recipeWords = /\b(style|estilo|receta|recipe|combo|familiar|para compartir|olla|plato|menu|menú|guisad|hornead|caser|al horno|en salsa|soup|stew)\b/i;
    
    // Detección de títulos en inglés para descartarlos
    const englishIndicators = /\b(soup|stew|and|with|chicken|beef|pork|fish|peas?|vegetable|roasted|fried|beans)\b/i;

    const parseMacro = (text, regex) => {
      const match = text.match(regex);
      if (!match) return 0;
      return parseFloat(match[1].replace(',', '.')) || 0;
    };

    const results = [];

    for (const item of allFoods) {
      const rawName = item.food_name || '';
      const normName = rawName.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

      // 1. Descartar si el nombre principal está en inglés
      if (englishIndicators.test(rawName) && !rawName.toLowerCase().includes('arroz')) {
        continue;
      }

      // 2. Descartar recetas y platos preparados
      if (recipeWords.test(rawName)) continue;

      // 3. COINCIDENCIA REAL: El alimento debe contener las palabras clave buscadas
      // (Si buscas "crema de arroz", debe tener "crema" y "arroz", no hierbas ni sopas)
      if (cleanQueryWords.length > 1) {
        const matchesAll = cleanQueryWords.every(word => normName.includes(word));
        if (!matchesAll) continue;
      }

      const desc = item.food_description || '';
      const kcal = Math.round(parseMacro(desc, /(?:Calories|Calorías):\s*([0-9.,]+)/i));

      // 4. Descartar aberraciones calóricas de ollas gigantes (> 900 kcal)
      if (kcal > 900 || (kcal === 0 && !normName.includes('agua'))) continue;

      const fat = parseFloat(parseMacro(desc, /(?:Fat|Grasa):\s*([0-9.,]+)g/i).toFixed(1));
      const carbs = parseFloat(parseMacro(desc, /(?:Carbs|Carb|Carbohidratos|Carbh):\s*([0-9.,]+)g/i).toFixed(1));
      const protein = parseFloat(parseMacro(desc, /(?:Protein|Proteína|Proteina|Prot):\s*([0-9.,]+)g/i).toFixed(1));

      results.push({
        code: `fs_${item.food_id}`,
        name: rawName,
        brand: item.brand_name || 'Genérico',
        kcal,
        protein,
        carbs,
        fat,
        fiber: 0,
        baseGrams: 100
      });
    }

    return res.status(200).json({ results });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
