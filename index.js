require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 5000;
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ynkon.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Middleware
app.use(cors({
    origin: [
        "http://localhost:5173"
    ],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized' })
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized' })
        }
        req.user = decoded;
        next();
    })
}

async function run() {
    try {
        const database = client.db("easy-cash");
        const usersCollection = database.collection('users');

        // Admin verification middleware
        const verifyAdmin = async (req, res, next) => {
            const query = {
                email: req.user.email,
                role: 0
            }
            const result = await usersCollection.findOne(query);
            if (!result) {
                return res.status(401).send({ message: 'Unauthorized' })
            }
            next();
        }

        // keeping seperate for reusing purpose
        const jwtInit = (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '5h' });
            return res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
            });
        }

        // Save credentials in database after sign up
        app.post('/create-user', async (req, res) => {
            const data = req.body;
            const emailQuery = {email: data.email}
            const mobileQuery = {mobile: data.mobile}
            const nidQuery = {nid: data.nid}

            const emailRes = await usersCollection.findOne(emailQuery);
            if(emailRes)return res.send({err: true, duplicateEmail: true})
                
            const mobileRes = await usersCollection.findOne(mobileQuery);
            if(mobileRes)return res.send({err: true, duplicateMobile: true})
                
            const nidRes = await usersCollection.findOne(nidQuery);
            if(nidRes)return res.send({err: true, duplicateNid: true})

            data.role = data.ac_type === 'user' ? 3 : 2;

            const salt = bcrypt.genSaltSync(10);
            data.pin = bcrypt.hashSync(data.pin, salt);
            const result = await usersCollection.insertOne(data);
            res.send(result);
        })

        // Login
        app.post('/login', async (req, res) => {
            const inValidMsg = { noAcc: true, message: "Invalid email or password!" }
            const email = req.body.email;
            const pin = req.body.pin;
            const query = { email }
            const result = await usersCollection.findOne(query);
            if (!result) return res.send(inValidMsg);

            const isPinOk = await bcrypt.compare(pin, result.pin);
            if (!isPinOk) return res.send(inValidMsg);

            delete result.pin;

            jwtInit(req, res).send(result);
            // res.send(result);
        })

        // Create JWT after sign in
        app.post('/jwt', async (req, res) => {
            const user = req.user;
            const token = req?.cookies?.token;
            if (!token) {
                return res.send({});
            }

            jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'Unauthorized' })
                }
                const user = decoded;

                const query = { email: user.email }
                const result = await usersCollection.findOne(query);
                if (!result) return res.status(404);
                res.send(result);
            })

        })

        // Clear cookie after logging out
        app.post('/logout', (req, res) => {
            res.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
            }).send({ success: true })
        })


    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.listen(port, () => {
    console.log(`Server is running at ${port}`)
})