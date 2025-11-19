const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs')
const cookieParser = require('cookie-parser');
const pool = require('./accessDB');
const cors = require('cors')
const https = require('https')
const fs = require('fs')
const path = require('path')

require('dotenv').config();

const app = express();

app.use(cors({
  origin: process.env.URL_WEB,
  credentials: true
}))
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || '5000';
const HOST = process.env.HOST || '0.0.0.0'
const SECRET = process.env.API_SECRET

const verifyToken = (req, res, next) => {
  const token = req.cookies.token
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token no proportioned'
    });
  }
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: 'Token invalid'
    });
  }
}

app.get('/',  (req, res) => {
  res.send('Api of workout tracker')
});

//ENDPOINTS User

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    const idQuery = Buffer.from(`${email}-${username}`).toString('base64');
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);

    if (rows.length !== 0) {
      return res.status(401).json({
        success: false,
        message: 'User already exists'
      });
    }

    const passHash = bcrypt.hashSync(password)

    await pool.execute('INSERT INTO users (id, username, password_hash, email) VALUES (?,?,?,?)',[idQuery, username, passHash, email])

    return res.status(201).json({
      success: true,
      message: 'User created successfully'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: register user'
    })
  }
});

app.post('/login/user', async (req, res) => {
  try {
    const { username, password } = req.body

    const [pass] = await pool.execute('SELECT password_hash FROM users WHERE username = ?', [username])

    if (pass.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Username missing or invalid'
      })
    }

    const passHash = bcrypt.compareSync(password, pass[0].password_hash)

    if (!passHash) {
      return res.status(401).json({
        success: false,
        message: 'Password is invalid'
      })
    }

    const [row] = await pool.query('SELECT id, username, email, photo FROM users WHERE username = ?', [username])

    if (row.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Credentials Invalid'
      })
    }

    if (!SECRET) {
      return res.status(500).json({
        success: false,
        message: 'Error get credentials'
      })
    }

    const payload = {
      id: row[0].id
    }
    const token = jwt.sign(payload, SECRET, {expiresIn: '7d'})

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 604800000,
    })

    res.status(200).json({
      success: true,
      message: 'Login successful',
    })
  } catch (error) {
    return res.status(500).json({
        success: false,
      message: 'Internal Server Error: login with username'
    })
  }
});

app.post('/login/email', async (req, res) => {
  try {
    const { email, password } = req.body

    const [pass] = await pool.execute('SELECT password_hash FROM users WHERE email = ?', [email])
    
    if (pass.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Email missing or invalid'
      })
    }

    const passHash = bcrypt.compareSync(password, pass[0].password_hash)

    if (!passHash) {
      return res.status(401).json({
        success: false,
        message: 'Password is invalid'
      })
    }

    const [row] = await pool.query('SELECT id, username, email, photo FROM users WHERE email = ?', [email])

    if (row.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Credentials Invalid'
      })
    }
    if (!SECRET) {
      return res.status(500).json({
        success: false,
        message: 'Error get credentials'
      })
    }

    const payload = {
      id: row[0].id
    }
    const token = jwt.sign(payload, SECRET, {expiresIn: '7d'})

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 604800000,
    })

    res.status(200).json({
      success: true,
      message: 'Login successful',
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: login with email'
    })
  }
});

//ENDPOINTS PRIVATE {**

app.use(verifyToken);

app.post('/logout', async (req, res) => {
  try {
    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
    })
    return res.status(200).json({
      success: true,
      message: 'Logout successful'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: logout user'
    })
  }
})

app.get('/user', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, username, email, photo FROM users WHERE id = ?', [req.user.id])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Token invalid or expired'
      })
    }

    res.status(200).json({
      success: true,
      message: 'User data get successfully',
      user: rows[0]
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server: Error get user data'
    })
  }
})

app.put('/user', async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Request malformed or invalid'
      })
    }

    const [user] = await pool.execute('SELECT username FROM users WHERE username = ?', [username])

    if (user.length !== 0) {
      return res.status(400).json({
        success: false,
        message: 'Username already exist'
      })
    }

    const [pass] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.id])

    const passHash = bcrypt.compareSync(password, pass[0].password_hash)

    if (!passHash) {
      return res.status(401).json({
        success: false,
        message: 'Password is invalid'
      })
    }


    await pool.execute('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id])

    res.status(200).json({
      success: true,
      message: 'Username update successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.put('/email', async (req, res) => {
  try {
    const { email, password } = req.body

    const [user] = await pool.execute('SELECT email FROM users WHERE email = ?', [email])

    if (user.length !== 0) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Email already exist'
      })
    }

    const [rows] = await pool.execute('SELECT id, username, email, photo FROM users WHERE id = ? AND password_hash = ?', [req.user.id, password])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Password wrong or invalid'
      })
    }

    await pool.execute('UPDATE users SET email = ? WHERE id = ?', [email, req.user.id])

    res.status(200).json({
      success: true,
      user: req.user.id,
      message: 'Username update successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.put('/pass', async (req, res) => {
  try {
    const { newPassword } = req.body

    const [pass] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.id])

    const passHash = bcrypt.compareSync(newPassword, pass[0].password_hash)

    if (passHash) {
      return res.status(401).json({
        success: false,
        message: 'Password already exist'
      })
    }
    
    const newPassHash = bcrypt.hashSync(newPassword)

    await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newPassHash, req.user.id])

    res.status(200).json({
      success: true,
      message: 'Password update successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.put('/photo', async (req, res) => {
  try {
    const { avatar } = req.body

    const [photo] = await pool.execute('SELECT photo FROM users WHERE id = ?', [req.user.id])

    if (photo === avatar) {
      return res.status(400).json({
        success: false,
        message: 'Avatar has already selected'
      })
    }

    await pool.execute('UPDATE users SET photo = ? WHERE id = ?', [avatar, req.user.id])

    res.status(200).json({
      success: true,
      message: 'Avatar updated successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.delete('/user', async (req, res)  => {
  try {
    const { password } = req.body

    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.id])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'User credentials missing or invalid'
      })
    }

    const passHash = bcrypt.compareSync(password, rows[0].password_hash)

    if (!passHash) {
      return res.status(401).json({
        success: false,
        message: 'Password is invalid'
      })
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [req.user.id])

    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
    })

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: Delete user'
    })
  }
})

//ENDPOINTS Routines

app.post('/routines', async (req, res) => {
  try {
    const { routine } = req.body

    const [rows] = await pool.execute('SELECT * FROM routines WHERE name = ? AND id_user = ?', [routine.name, req.user.id])

    if (rows.length !== 0) {
      return res.status(404).json({
        success: false,
        message: 'Routine already exists'
      })
    }

    await pool.execute('INSERT INTO routines(name, id_user) VALUES (?, ?)', [routine.name, req.user.id])

    res.status(201).json({
      success: true,
      message: 'Created routine successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.get('/routines', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name FROM routines WHERE id_user = ?', [req.user.id])

    res.status(200).json({
      success: true,
      message: 'Routine get successfully',
      routines: rows
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.get('/routines/exist', async (req, res) => {
  try {
    const { name } = req.query

    if(!name) {
      return res.status(400).json({
        success: false,
        message: 'Exercise missing or invalid'
      })
    }

    const [rows] = await pool.query('SELECT name FROM routines WHERE id_user = ? AND name = ?', [req.user.id, name])

    if (rows.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'Routine not already exist',
        isExists: false
      })
    }

    res.status(200).json({
      success: true,
      message: 'Routine already exist',
      isExists: true
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
});

app.put('/routines', async (req, res) => {
  try {
    const { routine } = req.body

    if (!routine || !routine.name || !routine.id) {
      return res.status(400).json({
        success: false,
        message: 'Routine data missing or invalid',
      })
    }

    const [rows] = await pool.execute('SELECT * FROM routines WHERE id = ?', [routine.id])

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Routine not exist'
      })
    }

    await pool.execute('UPDATE routines SET name = ? WHERE id = ?', [routine.name, routine.id])

    res.status(200).json({
      success: true,
      message: 'Routine update successfully',
      routine: routine
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.delete('/routines', async (req, res) => {
  try {
    const { routine } = req.body

    if (!routine || !routine.id) {
      return res.status(400).json({
        success: false,
        message: 'Routines data missing or invalid'
      })
    }

    const [rows] = await pool.execute('SELECT * FROM routines WHERE id = ?', [routine.id])
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ID routine wrong o invalid',
      })
    }

    await pool.execute('DELETE FROM routines WHERE id = ?', [routine.id])

    res.status(200).json({
      success: true,
      message: 'User routines were deleted',
      routinesDeleted: routine
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

//ENDPOINTS Exercises

app.post('/exercises', async (req, res) => {
  try {
    const { exercise } = req.body;

    if (!exercise || !exercise.name || !exercise.weight) {
      return res.status(400).json({
        success: false,
        message: 'Exercise data missing or invalid'
      });
    }

    await pool.execute(`INSERT INTO exercises(name, weight, id_user) VALUES (?, ?, ?)`, [exercise.name, exercise.weight, req.user.id]);

    res.status(201).json({
      success: true,
      message: 'Create exercise successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.get('/exercises/exist', async (req, res) => {
  try {
    const { name } = req.query

    if(!name) {
      return res.status(400).json({
        success: false,
        message: 'Exercise missing or invalid'
      })
    }

    const [rows] = await pool.query('SELECT name FROM exercises WHERE id_user = ? AND name = ?', [req.user.id, name])

    if (rows.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'Exercise not already exist',
        isExists: false
      })
    }

    res.status(200).json({
      success: true,
      message: 'Exercise already exist',
      isExists: true
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
});

app.get('/exercises', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, weight FROM exercises WHERE id_user = ?', [req.user.id])

    res.status(200).json({
      success: true,
      message: 'Successfully get exercises of user',
      exercises: rows
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.put('/exercises', async (req, res) => {
  try {
    const { exercise } = req.body

    if (!exercise || !exercise.id || !exercise.name || typeof exercise.weight !== 'number') {
      return res.status(400).json({
        success: false,
        message: 'Exercise missing or invalid'
      })
    }

    const [rows] = await pool.execute('SELECT * FROM exercises WHERE id = ?', [exercise.id])

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Exercise not exist'
      })
    }

    await pool.execute('UPDATE exercises SET name = ?, weight = ? WHERE id = ?', [exercise.name, exercise.weight, exercise.id])

    res.status(200).json({
      success: true,
      message: 'Successfully update exercise'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: Update exercise'
    })
  }
})

app.delete('/exercises', async (req, res) => {
  try {
    const { exercise } = req.body

    if (exercise.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Exercises missing or invalid'
      })
    }

    const [rows] = await pool.execute('SELECT * FROM exercises WHERE id = ?', [exercise.id])
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ID exercise wrong o invalid'
      })
    }

    await pool.execute('DELETE FROM exercises WHERE id = ?', [exercise.id])

    res.status(200).json({
      success: true,
      message: 'Successfully delete exercise of user'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

//ENDPOINTS Days

app.post('/days', async (req, res) => {
  try {
    const { days } = req.body

    if (!Array.isArray(days.data) || days.data.length === 0 || !days) {
      return res.status(400).json({
        success: false,
        message: 'Days data missing or malformed'
      })
    }

    const [user] = await pool.execute('SELECT name FROM routines WHERE id = ? AND id_user = ?', [days.id, req.user.id])

    if (user.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Routine not exist'
      })
    }

    for (const day of days.data) {
      if (!Array.isArray(day.exercises) || day.exercises.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Days(exercises) data missing or malformed'
        })
      }

      const [row] = await pool.execute('SELECT name FROM days WHERE id_routine = ? AND name = ?', [days.id, day.name])

      if (row.length !== 0) {
        return res.status(400).json({
          success: false,
          message: 'Day already exist in routine'
        })
      }

      for (const exercise of day.exercises) {
        const [rows] = await pool.execute('SELECT name FROM days WHERE id_routine = ? AND name = ? AND id_exercise', [days.id, day.name, exercise])

        if (rows.length !== 0) {
          return res.status(400).json({
            success: false,
            message: 'Exercises of day already exist in routine'
          })
        }

        await pool.execute('INSERT INTO days(name, id_routine, id_exercise) VALUES (?, ?, ?)', [day.name, days.id, exercise])
      }
    }

    res.status(201).json({
      success: true,
      message: 'Days of exercise were created successfully',
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.get('/days', async (req, res) => {
  try {
    const { routine } = req.query
    const data = []
    
    if (!routine) {
      return res.status(400).json({
        success: false,
        message: 'routine data missing or invalid'
      })
    }

    const [days] = await pool.execute('SELECT name FROM days WHERE id_routine = ? GROUP BY name', [routine])

    if (days.length === 0) {
      return res.status(200).json({
        success: false,
        message: 'No days found for the specified routine',
      })
    }

    for await (const day of days) {
      const [exercises] = await pool.execute('SELECT id_exercise FROM days WHERE name = ? AND id_routine = ?', [day.name, routine])
      const id = exercises.flatMap(exercise => exercise.id_exercise)
      data.push({
        name: day.name,
        exercises: id
      })
    }

    res.status(200).json({
      success: true,
      message: 'Days of routine get successfully',
      days: data
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.put('/days', async (req, res) => {
  try {
    const { routine } = req.body

    if (!routine.id || !Array.isArray(routine.days)) {
      return res.status(400).json({
        success: false,
        message: 'Exercises without data or malformed'
      })
    }

    await pool.execute('DELETE FROM days WHERE id_routine = ?', [routine.id])

    for await (const day of routine.days) {
      for await (const exercise of day.exercises) {
        await pool.execute('INSERT INTO days(name, id_routine, id_exercise) VALUES (?, ?, ?)', [day.name, routine.id, exercise])
      }
    }

    res.status(200).json({
      success: true,
      message: 'Day update successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.delete('/days', async (req, res) => {
  try {
    const { routine } = req.body

    if (!routine) {
      return res.status(400).json({
        success: false,
        message: 'Days without data or malformed'
      })
    }

    const [rows] = await pool.execute('SELECT id FROM days WHERE id_routine = ?', [routine])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Days not exist'
      })
    }

    await pool.execute('DELETE FROM days WHERE id_routine = ?', [routine])

    res.status(200).json({
      success: true,
      message: 'Days deleted successfully',
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

// **}

app.listen(PORT, HOST, () => {
  console.log(`Server listen on http://${HOST}:${PORT}`)
})