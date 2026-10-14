const crypto = require('crypto');

// Codificación estricta RFC 3986 requerida por el protocolo OAuth 1.0 de FatSecret
function rfc3986(str) {
  return encodeURIComponent(String(str)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

module.exports = async (req, res) => {
  // Encabezados de CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const query = req.query.q;
  if (!query) return res.status(200).json({ results: [] });

  const consumerKey = process.env.FATSECRET_CLIENT_ID;
  const consumerSecret = process.env.FATSECRET_CLIENT_SECRET;

  if (!consumerKey || !consumerSecret) {
    return res.status(500).json({
      error: 'Faltan variables FATSECRET_CLIENT_ID y FATSECRET_CLIENT_SECRET en las Variables de Entorno de Vercel'
    });
  }

  try {
    const httpMethod = 'GET';
    const baseUrl = 'https://platform.fatsecret.com/rest/server.api';

    // 1. Parámetros de la consulta: región México en español
    const params = {
      format: 'json',
      language: 'es',
      max_results: '15', // Solicitamos 15 para compensar las recetas que descartamos
      method: 'foods.search',
      oauth_consumer_key: consumerKey.trim(),
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
      region: 'MX',
      search_expression: query.trim()
    };

    // 2. Ordenar alfabéticamente los parámetros
    const sortedKeys = Object.keys(params).sort();
    const paramString = sortedKeys.map(k => `${rfc3986(k)}=${rfc3986(params[k])}`).join('&');

    // 3. Crear la cadena base de la firma
    const signatureBaseString = `${httpMethod}&${rfc3986(baseUrl)}&${rfc3986(paramString)}`;

    // 4. Clave de firma criptográfica (Consumer Secret + &)
    const signingKey = `${rfc3986(consumerSecret.trim())}&`;

    // 5. Generar la firma HMAC-SHA1
    const signature = crypto.createHmac('sha1', signingKey).update(signatureBaseString).digest('base64');

    // 6. Construir la URL completa con la firma
    const requestUrl = `${baseUrl}?${paramString}&oauth_signature=${rfc3986(signature)}`;

    // 7. Petición oficial a FatSecret
    const apiRes = await fetch(requestUrl);
    const searchResponse = await apiRes.json().catch(() => ({}));

    // Detectar si FatSecret devolvió algún error
    if (searchResponse.error) {
      throw new Error(`FatSecret Error (${searchResponse.error.code}): ${searchResponse.error.message}`);
    }

    const rawFoods = searchResponse.foods?.food;
    const allFoods = Array.isArray(rawFoods) ? rawFoods : (rawFoods ? [rawFoods] : []);

    // 8. FILTRO ANTIRECETAS: Descarta platos compuestos, combos y estilos de restaurante
    const recipePattern = /(?:style|estilo|receta|recipe|combo|menú|menu|preparado con|guisado con|al horno con|a la criolla)/i;
    const foodList = allFoods.filter(item => !recipePattern.test(item.food_name || ''));

    // Función auxiliar para extraer números con coma o punto decimal
    const parseMacro = (text, regex) => {
      const match = text.match(regex);
      if (!match) return 0;
      return parseFloat(match[1].replace(',', '.')) || 0;
    };

    // 9. Mapeo de macronutrientes al formato exacto de tu aplicación
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
