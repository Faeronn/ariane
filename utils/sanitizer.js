function sanitizeInput(input) {
	if (typeof input === 'string') return input.replace(/[<>'"]/g, '');
	return input;
}

module.exports = sanitizeInput;
