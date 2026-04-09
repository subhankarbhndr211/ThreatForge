'use strict';
const express = require('express');
const router  = express.Router();
router.get('/', (req, res) => res.json({ status: 'TI route active' }));
module.exports = router;
