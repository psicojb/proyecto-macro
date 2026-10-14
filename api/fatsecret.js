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

    // Solicitamos 40 resultados para que no se oculte la crema de arroz
    const params = {
      format: 'json',
      language: 'es',
      max_results: '40',
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

    // 1. FILTRO DE PALABRAS: Eliminar recetas, combos y preparaciones de restaurante
    const recipeWords = /\b(style|estilo|receta|recipe|combo|familiar|para compartir|olla|plato|menu|menú|guisad|hornead|caser|al horno|en salsa|con queso|con pollo)\b/i;
    
    const parseMacro = (text, regex) => {
      const match = text.match(regex);
      if (!match) return 0;
      return parseFloat(match[1].replace(',', '.')) || 0;
    };

    const results = [];

    for (const item of allFoods) {
      const name = item.food_name || '';
      if (recipeWords.test(name)) continue; // Descarta recetas por nombre

      const desc = item.food_description || '';
      const kcal = Math.round(parseMacro(desc, /(?:Calories|Calorías):\s*([0-9.,]+)/i));

      // 2. FILTRO DE CALORÍAS: Si tiene más de 900 kcal es una olla/receta familiar gigante (se descarta)
      if (kcal > 900 || (kcal === 0 && !name.toLowerCase().includes('agua'))) continue;

      const fat = parseFloat(parseMacro(desc, /(?:Fat|Grasa):\s*([0-9.,]+)g/i).toFixed(1));
      const carbs = parseFloat(parseMacro(desc, /(?:Carbs|Carb|Carbohidratos|Carbh):\s*([0-9.,]+)g/i).toFixed(1));
      const protein = parseFloat(parseMacro(desc, /(?:Protein|Proteína|Proteina|Prot):\s*([0-9.,]+)g/i).toFixed(1));

      results.push({
        code: `fs_${item.food_id}`,
        name: name,
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
