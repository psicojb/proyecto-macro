const crypto = require('crypto');

// Codificación estricta RFC 3986 requerida por FatSecret OAuth 1.0
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
    return res.status(500).json({
      error: 'Faltan variables FATSECRET_CLIENT_ID y FATSECRET_CLIENT_SECRET en Vercel'
    });
  }

  try {
    const httpMethod = 'GET';
    const baseUrl = 'https://platform.fatsecret.com/rest/server.api';

    // Parámetros de consulta y firma OAuth 1.0
    const params = {
      format: 'json',
      language: 'es',
      max_results: '10',
      method: 'foods.search',
      oauth_consumer_key: consumerKey.trim(),
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
      region: 'MX',
      search_expression: query.trim()
    };

    // 1. Ordenar los parámetros alfabéticamente
    const sortedKeys = Object.keys(params).sort();
    const paramString = sortedKeys.map(k => `${rfc3986(k)}=${rfc3986(params[k])}`).join('&');

    // 2. Crear la cadena base de la firma (Signature Base String)
    const signatureBaseString = `${httpMethod}&${rfc3986(baseUrl)}&${rfc3986(paramString)}`;

    // 3. Crear la clave de firma (Consumer Secret + &)
    const signingKey = `${rfc3986(consumerSecret.trim())}&`;

    // 4. Generar la firma HMAC-SHA1
    const signature = crypto.createHmac('sha1', signingKey).update(signatureBaseString).digest('base64');

    // 5. URL final con la firma incorporada
    const requestUrl = `${baseUrl}?${paramString}&oauth_signature=${rfc3986(signature)}`;

    // 6. Consultar a FatSecret
    const apiRes = await fetch(requestUrl);
    const searchResponse = await apiRes.json().catch(() => ({}));

    // Detectar si FatSecret reporta algún error de credenciales
    if (searchResponse.error) {
      throw new Error(`FatSecret Error (${searchResponse.error.code}): ${searchResponse.error.message}`);
    }

    const rawFoods = searchResponse.foods?.food;
    const foodList = Array.isArray(rawFoods) ? rawFoods : (rawFoods ? [rawFoods] : []);

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