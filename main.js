require('dotenv').config();
const authRouter = require('./routes/auth');

const bodyParser = require('body-parser');
const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.PORT;

//TODO : Security hardening with limiters, IP filters ect
//Why not using an Interceptor for that
app.use((req, res, next) => {
	bodyParser.json()(req, res, err => {
		if (err) return res.status(400).send({ message: 'Error : Bad JSON formatting.' });

		return next();
	});
});
app.use(cors());

// Routes
app.use('/auth', authRouter);

app.listen(port, () => { console.log(`Server running on http://localhost:${port}`); });
