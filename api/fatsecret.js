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

    // Pedimos 40 resultados para que alimentos como "crema de arroz" nunca se queden por fuera
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

    // FILTRO RIGUROSO ANTIRECETAS (Descarta platos compuestos pero conserva ingredientes puros)
    const recipePattern = /\b(style|estilo|receta|recipe|combo|menú|menu|guisad[oa]|hornead[oa]|frit[oa]\s+con|al\s+horno|a\s+la|al\s+ajillo|en\s+salsa|caser[oa]|homemade|plato|ensalada\s+de|sopa\s+de|caldo\s+de|tacos?\s+de|burritos?|fajitas?|guarnici[oó]n|con\s+queso|con\s+papas|con\s+arroz)\b/i;
    const foodList = allFoods.filter(item => !recipePattern.test(item.food_name || ''));

    const parseMacro = (text, regex) => {
      const match = text.match(regex);
      if (!match) return 0;
      return parseFloat(match[1].replace(',', '.')) || 0;
    };

    const results = foodList.map(item => {
      const desc = item.food_description || '';
      const kcal = Math.round(parseMacro(desc, /(?:Calories|Calorías):\s*([0-9.,]+)/i));
      const fat = parseFloat(parseMacro(desc, /(?:Fat|Grasa):\s*([0-9.,]+)g/i).toFixed(1));
      const carbs = parseFloat(parseMacro(desc, /(?:Carbs|Carb|Carbohidratos|Carbh):\s*([0-9.,]+)g/i).toFixed(1));
      const protein = parseFloat(parseMacro(desc, /(?:Protein|Proteína|Proteina|Prot):\s*([0-9.,]+)g/i).toFixed(1));

      return {
        code: `fs_${item.food_id}`,
        name: item.food_name,
        brand: item.brand_name || 'Genérico',
        kcal,
        protein,
        carbs,
        fat,
        fiber: 0,
        baseGrams: 100
      };
    });

    return res.status(200).json({ results });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
