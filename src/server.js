const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
require('dotenv').config();
// const { default: mongoose } = require('mongoose');
const mongoose = require('mongoose');
const routes = require('./routes')
const app = express()
const fileUpload = require('express-fileupload');


app.use(cors())
app.use(fileUpload());


app.use(bodyParser.urlencoded({extended:false}))
app.use(bodyParser.json())
app.use("/apis", routes);
// mongoose.connect(process.env.DB_URL)

// Connect to MongoDB
mongoose.connect(process.env.DB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
    // Your code here
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB', error);
  });

const port = process.env.PORT || 3000
const server = app.listen(port, () => {
    console.log(`Server is running at port ${port}`)
})