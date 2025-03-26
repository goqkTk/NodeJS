const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
app.use(express.json());
const PORT = 3000;
const JWT_SECRET = 'ggooqqkkTTkk';
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

app.listen(PORT, () => {
    console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});

// SQLite3 데이터베이스 연결
const db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error("DB 연결 실패:", err.message);
    } else {
        console.log("DB 연결됨");
    }
});

db.serialize(() => {
    // users 테이블 생성
    db.run(`CREATE TABLE IF NOT EXISTS users (
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL
    )`);

    // 게시글 테이블 생성
    db.run(`CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        username TEXT NOT NULL,
        date TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // 댓글 테이블 생성
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        article_id INTEGER NOT NULL,
        FOREIGN KEY (article_id) REFERENCES articles(id)
    )`);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.post('/register', (req, res) => {
    const { username, password, email } = req.body;

    // 비밀번호 해싱
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("비밀번호 해싱 실패:", err.message);
            return res.status(500).json({ error: "비밀번호 해싱에 실패했습니다." });
        }

        // 사용자 등록
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], function(err) {
            if (err) {
                return res.status(500).json({ error: '회원가입 실패' });
            }
            res.status(200).json({ success: true, message: '회원가입 성공!' });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // 사용자 정보 조회
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) {
            console.error("사용자 조회 실패:", err.message);
            return res.status(500).json({ error: "사용자 조회에 실패했습니다." });
        }

        if (!row) {
            return res.status(400).json({ error: "사용자가 존재하지 않습니다." });
        }

        // 비밀번호 비교
        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                console.error("비밀번호 비교 실패:", err.message);
                return res.status(500).json({ error: "비밀번호 비교에 실패했습니다." });
            }

            if (result) {
                // JWT 생성
                const token = jwt.sign({ username: row.username, email: row.email }, JWT_SECRET, { expiresIn: '1h' });

                // JWT를 클라이언트에게 반환
                res.status(200).json({ message: "로그인 성공!", token });
            } else {
                res.status(400).json({ error: "비밀번호가 틀렸습니다." });
            }
        });
    });
});

// JWT 인증 미들웨어
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ error: '토큰이 없습니다.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: '유효하지 않은 토큰입니다.' });
        }

        req.user = user;
        next();
    });
};

// 보호된 API 예시 (JWT 검증 필요)
app.get('/protected', authenticateJWT, (req, res) => {
    res.status(200).json({ message: `안녕하세요, ${req.user.username}님!` });
});