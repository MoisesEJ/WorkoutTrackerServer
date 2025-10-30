const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs')
const cookieParser = require('cookie-parser');
const pool = require('./accessDB');

require('dotenv').config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const URL = process.env.URL || 'http://localhost:5000'
const SECRET = process.env.API_SECRET || null

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization']

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization header missing or malformed' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido' });
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
        message: 'Missing required fields'
      });
    }

    const idQuery = Buffer.from(`${email}-${username}`).toString('base64');
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);

    if (rows.length !== 0) {
      return res.status(401).json({
        message: 'User already exists'
      });
    }

    await pool.execute('INSERT INTO users (id, username, password_hash, email) VALUES (?,?,?,?)',[idQuery, username, password, email])

    return res.status(201).json({
      message: 'User created successfully'
    });
  } catch (error) {
    return res.status(500).json({
      message: 'Internal Server Error: register user'
    })
  }
});

app.get('/login/user', async (req, res) => {
  try {
    const { username, password } = req.body
    const [row] = await pool.query('SELECT id, username, email, photo FROM users WHERE username = ? AND password_hash = ?', [username, password])

    if (row.lenght === 0) {
      return res.status(401).json({
        message: 'Credentials Invalid'
      })
    }
    if (!SECRET) {
      return res.status(500).json({
        message: 'Error get credentials'
      })
    }

    const payload = {
      id: row[0].id
    }
    const token = jwt.sign(payload, SECRET, {expiresIn: '7d'})

    res.status(200).json({token})
  } catch (error) {
    return res.status(500).json({
      message: 'Internal Server Error: login with username'
    })
  }
});

app.get('/login/email', async (req, res) => {
  try {
    const { email, password } = req.body
    const [row] = await pool.query('SELECT id, username, email, photo FROM users WHERE email = ? AND password_hash = ?', [email, password])

    if (row.lenght === 0) {
      return res.status(401).json({
        message: 'Credentials Invalid'
      })
    }
    if (!SECRET) {
      return res.status(500).json({
        message: 'Error get credentials'
      })
    }

    const payload = {
      id: row[0].id
    }
    const token = jwt.sign(payload, SECRET, {expiresIn: '7d'})

    res.status(200).json({token})
  } catch (error) {
    return res.status(500).json({
      message: 'Internal Server Error: login with email'
    })
  }
});

//ENDPOINTS PRIVATE {**

app.use(verifyToken);

app.get('/user', async (req, res) => {
  try {
    console.log(req.user)
    const [rows] = await pool.execute('SELECT id, username, email, photo FROM users WHERE id = ?', [req.user.id])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Token ivanlid or expired'
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

app.put('/change/user', async (req, res) => {
  try {
    const { username, password } = req.body

    const [user] = await pool.execute('SELECT username FROM users WHERE username = ?', [username])

    if (user.length !== 0) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Username already exist'
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

    await pool.execute('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id])

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

app.put('/change/email', async (req, res) => {
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

app.put('/change/pass', async (req, res) => {
  try {
    const { newpassword } = req.body

    const [pass] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.id])

    if (pass[0].password_hash === newpassword) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Password already exist'
      })
    }

    await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newpassword, req.user.id])

    res.status(200).json({
      success: true,
      user: req.user.id,
      message: 'Password update successfully'
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

app.delete('/delete/user', async (req, res)  => {
  try {
    const [rows] = await pool.execute('SELECT id, username FROM users WHERE id = ?', [req.user.id])

    if (rows.lenght === 0) {
      return res.status(400).json({
        success: false,
        message: 'ID user missing or invalid'
      })
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [req.user.id])

    res.status(200).json({
      success: true,
      message: 'User deleted successfully',
      userDeleted: req.user.id
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error: Not'
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
        user: req.user.id,
        message: 'Routine already exists'
      })
    }

    await pool.execute('INSERT INTO routines(name, id_user) VALUES (?, ?)', [routine.name, req.user.id])

    res.status(201).json({
      success: true,
      user: req.user.id,
      message: 'Created rutine successfully'
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
      message: 'Rutine get successfully',
      user: req.user.id,
      data: rows
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
        user: req.user.id,
        message: 'Routine data missing or invalid',
      })
    }

    const [rows] = await pool.execute('SELECT * FROM routines WHERE id = ?', [routine.id])

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        user: req.user.id,
        message: 'Routine not exist'
      })
    }

    await pool.execute('UPDATE routines SET name = ? WHERE id = ?', [routine.name, routine.id])

    res.status(200).json({
      success: true,
      user: req.user.id,
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
    const { routines } = req.body

    if (routines.lenght === 0) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Routines data missing or invalid'
      })
    }

    for (const routine of routines) {
      const [rows] = await pool.execute('SELECT * FROM routines WHERE id = ?', [routine.id])
        if (rows.length === 0) {
          return res.status(404).json({
            success: false,
            user: req.user.id,
            message: 'ID routine wrong o invalid',
            routineWrong: routines
          })
        }
    }

    await Promise.all(
      routines.map(routine => {
        pool.execute('DELETE FROM routines WHERE id = ?', [routine.id])
      })
    )

    res.status(200).json({
      success: true,
      user: req.user.id,
      message: 'User routines were deleted',
      routinesDeleted: routines
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
    const { exercises } = req.body;

    if (!Array.isArray(exercises) || exercises.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No exercises provided'
      });
    }

    const placeholders = exercises.map(() => '(?, ?, ?)').join(', ');
    const values = exercises.flatMap(exercise => [exercise.name, exercise.weight, req.user.id]);

    await pool.execute(`INSERT INTO exercises(name, weight, id_user) VALUES ${placeholders}`, values);

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
      user: req.user.id,
      data: rows
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
        user: req.user.id,
        message: 'Exercise missing or invalid'
      })
    }

    const [rows] = await pool.execute('SELECT * FROM exercises WHERE id = ?', [exercise.id])

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        user: req.user.id,
        message: 'Exercise not exist'
      })
    }

    await pool.execute('UPDATE exercises SET name = ?, weight = ? WHERE id = ?', [exercise.name, exercise.weight, exercise.id])

    res.status(200).json({
      success: true,
      user: req.user.id,
      message: 'Successfully update exercise',
      exercise: exercise
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      user: req.user.id,
      message: 'Internal Server Error: Update exercise'
    })
  }
})

app.delete('/exercises', async (req, res) => {
  try {
    const { exercises } = req.body

    if (exercises.lenght === 0) {
      return res.status(400).json({
        success: false,
        user: req.user.id,
        message: 'Exercises missing or invalid'
      })
    }

    for (const exercise of exercises) {
      const [rows] = await pool.execute('SELECT * FROM exercises WHERE id = ?', [exercise.id])
        if (rows.length === 0) {
          return res.status(404).json({
            success: false,
            user: req.user.id,
            message: 'ID exercise wrong o invalid',
            exerciseWrong: exercise
          })
        }
    }

    await Promise.all(
      exercises.map(exercise => {
        pool.execute('DELETE FROM exercises WHERE id = ?', [exercise.id])
      })
    )

    res.status(200).json({
      success: true,
      user: req.user.id,
      message: 'Successfully delete exercise of user',
      exerciseDeleted: exercises
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
      if (!Array.isArray(day.exercises) || day.exercises.lenght === 0) {
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
      message: 'Days of exericse were created successfully',
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
      return res.status(400).json({
        success: false,
        message: 'ID routine missing or invalid'
      })
    }

    for await (const day of days) {
      const [exercises] = await pool.execute('SELECT id_exercise FROM days WHERE name = ?', [day.name])
      const id = exercises.flatMap(exercise => exercise.id_exercise)
      data.push({
        name: day.name,
        exercises: id
      })
    }

    res.status(200).json({
      success: true,
      message: 'Days od routine get successfully',
      days: {
        id: routine,
        data: data
      }
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
    const { days } = req.body

    if (!Array.isArray(days.exercises) || days.exercises.lenght === 0 || !days.routine || !days.name) {
      return res.status(400).json({
        success: false,
        message: 'Exercises without data or malformed'
      })
    }

    const [rows] = await pool.execute('SELECT id, id_exercise FROM days WHERE id_routine = ? AND name = ?', [days.routine, days.name])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Exercises day not exist'
      })
    }

    for await (const row of rows) {
      await pool.execute('DELETE FROM days WHERE id = ?', [row.id])
    }

    for await (const exercise of days.exercises) {
      await pool.execute('INSERT INTO days(name, id_routine, id_exercise) VALUES (?, ?, ?)', [days.name, days.routine, exercise])
    }

    const [updated] = await pool.execute('SELECT id, id_exercise FROM days WHERE id_routine = ? AND name = ?', [days.routine, days.name])

    res.status(200).json({
      success: true,
      message: 'Day update successfully',
      exercisesUpdated: updated
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
    const { days } = req.body

    if (!days.routine || !days.name) {
      return res.status(400).json({
        success: false,
        message: 'Day without data or malformed'
      })
    }

    const [rows] = await pool.execute('SELECT id FROM days WHERE id_routine = ? AND name = ?', [days.routine, days.name])

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Day not exist'
      })
    }

    await pool.execute('DELETE FROM days WHERE id_routine = ? AND name = ?', [days.routine, days.name])

    res.status(200).json({
      success: true,
      message: 'Day deleted successfully',
      dayDeleted: days
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    })
  }
})

// **}

app.listen(PORT, () => {
  console.log(`Server is running on ${URL}`);
});