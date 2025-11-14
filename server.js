const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');
const { protect, authorize } = require('./src/middleware/auth.middleware');
const pool = require('./src/config/db');


const app = express();
app.set('trust proxy', 1); // Trust first proxy

// Middleware 
app.use(cors());
app.use(helmet());
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT;

// --------------EMAIL CONFIGURATION-----------------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


// Mail Sender Function
function send () {
  transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.log('Error:', error);
  }
  console.log('Email sent:', info.response);
})
};
// send()


// -------------DATABASE ALERT FUNCTION---------------- 
const sendAlert = async (error) => {
  const databaseErrorMailOptions = {
    from: '"Betternship Paperless FMS" <abc@test.betternship.com.ng>',
    to: process.env.TO_ALERT_EMAIL,
    subject: 'Betternship Database Connection Error Alert',

    text: `An error occurred:\n\n${error.stack}`,
  };

  try {
    await transporter.sendMail(databaseErrorMailOptions);
    console.log('Alert email sent.');
  } catch (err) {
    console.error('Failed to send alert email:', err);
  }
};

// Restart logic (graceful exit)
const restartApp = () => {
  console.log('Restarting app due to critical DB error...');
  process.exit(1); // Let a process manager like PM2 or Docker restart it
};

// Handle unexpected errors on idle clients
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client:', err);

  // Wrap async call in an IIFE to use await
  (async () => {
    try {
      await sendAlert(err);
    } catch (emailErr) {
      console.error('Failed to send alert email:', emailErr);
    }

    restartApp(); // Restart the app on critical DB errors
  })();
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down database pool...');
  await pool.end();
  console.log('Pool has ended');
  process.exit(0);
});

// Simple route for testing
// Test Route
app.get('/', (req, res) => {
  pool.connect((err) => {
    if (err) {
      res.send('Failed to run Backend!');
    } else {
      console.log('Backend Running!')
      res.send('Betternship  Backend Running!'); 

    }
  });
});

// Mock Data
const notes = [
  { "id": 1, "title": "Buy milk", "content": "2 liters" },
  { "id": 2, "title": "Call Sam", "content": "Discuss roadmap" }
];

// console.log("Curent Notes: ", notes)

app.post('/api/notes', async (req, res) => {
  try{
    const { noteTitle, noteContent } = req.body;
    // console.log("NoteTitle: ", noteTitle, "NoteContent: ", noteContent);

    // Add the new note to the array of notes
    notes.push({ id: notes.length + 1, title: noteTitle, content: noteContent });
    console.log("New Notes: ", notes)
    res.status(201).json(notes);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add note' });

  }
})

app.get('/api/notes', (req, res) => {
  // get notes
  res.json(notes);
});

app.put('/api/notes/:id', (req, res) => {
  // edit note by ID
  try {
    const noteId = parseInt(req.params.id);
    const { title, content } = req.body;

    const noteIndex = notes.findIndex((note) => note.id === noteId);
    
    if (noteIndex === -1) {
      return res.status(404).json({ error: 'Note not found' });
    }

    // Update the note
    notes[noteIndex] = { ...notes[noteIndex], title, content };
    // console.log("Updated Notes: ", notes);

    res.status(200).json(notes[noteIndex]);
  } catch (error) {
    // console.error('Error updating note:', error);
    res.status(500).json({ error: 'Failed to update note' });
  }
});

app.delete('/api/notes/:id', (req, res) => {
  try {
    const noteId = parseInt(req.params.id);

    const noteIndex = notes.findIndex((note) => note.id === noteId);
    
    if (noteIndex === -1) {
      return res.status(404).json({ error: 'Note not found' });
    }

    // Remove the note from the array
    const deletedNote = notes.splice(noteIndex, 1);
    // console.log("Deleted Note: ", deletedNote[0]);
    // console.log("Remaining Notes: ", notes);

    res.status(200).json({ message: 'Note deleted successfully', data: deletedNote[0] });
  } catch (error) {
    // console.error('Error deleting note:', error);
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


module.exports = app;