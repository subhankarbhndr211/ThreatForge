const express = require('express');
const router = express.Router();

router.get('/api/refresh-countdown', (req, res) => {
  // TODO: Add try/catch error handling
  try {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
    } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});
  
  // Send initial data (adjust based on your actual refresh interval)
  const data = { seconds: 600 }; // 10 minutes until next refresh
  res.write(`data: ${JSON.stringify(data)}\n\n`);
  
  // Update every second
  const interval = setInterval(() => {
    data.seconds = Math.max(0, data.seconds - 1);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
    
    if (data.seconds <= 0) {
      clearInterval(interval);
      res.end();
    }
  }, 1000);
  
  req.on('close', () => {
    clearInterval(interval);
    res.end();
    } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;