const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const app = express();
const port = 3000;

// Serve static files from the "public" directory
app.use(express.static('public'));

// Route to handle running the Go program
app.get('/run-go', (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).send('Domain is required');
  }
  
  const command = `go run "k:\\ADeskTop\\DNSpectr\\test.go" -d ${domain} -mod 2`;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error executing Go program: ${error.message}`);
      return res.status(500).send(`Error executing Go program: ${error.message}`);
    }

    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return res.status(500).send(`Backend program error: ${stderr}`);
    }

    console.log(`stdout: ${stdout}`);
    res.send(`Backend program executed successfully. Output: ${stdout}`);
  });
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});