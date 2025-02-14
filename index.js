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
        const transactionCollection = database.collection('transactions');

        // Admin verification middleware
        const verifyAdmin = async (req, res, next) => {
            const query = {
                email: req.user.email,
                role: 1
            }
            const result = await usersCollection.findOne(query);
            if (!result) {
                return res.status(401).send({ message: 'Unauthorized' })
            }
            next();
        }

        // blocking and unblocking account
        app.patch("/account-restriction/", verifyToken, verifyAdmin, async (req, res) => {
            const action = req.body.action;
            const email = req.body.email;

            const result = await usersCollection.updateOne({ email }, {
                $set: {
                    status: action
                }
            })

            res.send(result);
        })

        // Loading accounts (users/agents)
        app.get("/accounts", verifyToken, verifyAdmin, async (req, res) => {
            const type = req.query.type;
            const mobile = req?.query?.phone;
            const query = { ac_type: type };
            if (mobile) query.mobile = mobile;

            const cursor = usersCollection.find(query);
            const result = await cursor.toArray();
            res.send(result);
        })

        // View transaction by admin
        app.get("/transactions", verifyToken, verifyAdmin, async (req, res) => {
            const email = req.query.email;
            const cursor = transactionCollection.find({ $or: [{ from: email }, { to: email }] });
            const result = await cursor.toArray();
            res.send(result);
        })

        // check whether a user is a an agent
        app.get("/is-admin", verifyToken, async (req, res) => {
            const email = req.user.email;
            const result = await usersCollection.findOne({ email });
            res.send({ isAdmin: result?.role === 1 })
        })

        // check whether a user is a an agent
        app.get("/is-agent", verifyToken, async (req, res) => {
            const email = req.user.email;
            const result = await usersCollection.findOne({ email });
            res.send({ isAgent: result?.role === 2 })
        })

        // check whether a user is a normal user
        app.get("/is-user", verifyToken, async (req, res) => {
            const email = req.user.email;
            const result = await usersCollection.findOne({ email });
            res.send({ isUser: result?.role === 3 })
        })

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

        // Send money operation
        app.post("/send-money", verifyToken, async (req, res) => {
            const email = req.user.email;
            const recipient = req.body.recipient;
            const _amount = parseInt(req.body.amount);
            const charge = _amount < 100 ? 0 : 5;
            const amount = _amount + charge;

            const getRecipient = await usersCollection.findOne({ mobile: recipient });

            // checking whether both sender and reciver are same or not
            if (!getRecipient || email === getRecipient.email) {
                return res.send({ err: true, message: "Invalid recipient" });
            }

            if (getRecipient.ac_type !== 'user') {
                return res.send({ err: true, message: "Only users all allowed to be recipient!" });
            }

            const getSender = await usersCollection.findOne({ email });
            if (getSender.balance < amount) {
                return res.send({ err: true, message: "Insufficient balance!" });
            }

            await usersCollection.updateOne({ email }, {
                $inc: {
                    balance: - amount
                }
            });

            await usersCollection.updateOne({ mobile: recipient }, {
                $inc: {
                    balance: amount - charge
                }
            })

            charge > 0 && await usersCollection.updateOne({ role: 1 }, {
                $inc: {
                    balance: 5
                }
            })

            const salt = bcrypt.genSaltSync(10);
            const date = Date.now();
            const trxId = bcrypt.hashSync(date.toString(), salt);
            const transaction = {
                type: 'send-money',
                amount: amount - 5,
                charge: 5,
                sender: email,
                recipient: getRecipient.email,
                date,
                trxId
            }

            const result = await transactionCollection.insertOne(transaction);

            res.send({ ...result, trxId });
        })

        // Cash in operation
        app.post("/cash-in", verifyToken, async (req, res) => {
            const email = req.user.email;
            const user = req.body.user;

            const amount = parseInt(req.body.amount);

            const getUser = await usersCollection.findOne({ mobile: user });
            if (!getUser || getUser?.ac_type !== 'user') {
                return res.send({ err: true, message: "Invalid agent!" });
            }

            const getAgent = await usersCollection.findOne({ email });
            if (getAgent.balance < amount) {
                return res.send({ err: true, message: "Insufficient balance!" });
            }

            const isPinOk = await bcrypt.compare(req.body.pin, getAgent.pin);
            if (!isPinOk) {
                return res.send({ err: true, message: "Incorrect Pin!" });
            }

            await usersCollection.updateOne({ email }, {
                $inc: {
                    balance: - amount
                }
            });

            await usersCollection.updateOne({ mobile: getUser.mobile }, {
                $inc: {
                    balance: amount
                }
            })

            const salt = bcrypt.genSaltSync(10);
            const date = Date.now();
            const trxId = bcrypt.hashSync(date.toString(), salt);
            const transaction = {
                type: 'cash-in',
                amount: amount,
                charge: 0,
                from: email,
                to: getUser.email,
                date,
                trxId
            }

            const result = await transactionCollection.insertOne(transaction);

            res.send({ ...result, trxId });
        })

        // Cash out operation
        app.post("/cash-out", verifyToken, async (req, res) => {
            const email = req.user.email;
            const agent = req.body.agent;

            const _amount = parseInt(req.body.amount);
            const charge = _amount * (1.5 / 100);
            const amount = _amount + charge;

            const getAgent = await usersCollection.findOne({ mobile: agent });
            if (!getAgent || getAgent?.ac_type !== 'agent' || getAgent?.status !== 'approved') {
                return res.send({ err: true, message: "Invalid agent!" });
            }

            const getUser = await usersCollection.findOne({ email });
            if (getUser.balance < amount) {
                return res.send({ err: true, message: "Insufficient balance!" });
            }

            const isPinOk = await bcrypt.compare(req.body.pin, getUser.pin);
            if (!isPinOk) {
                return res.send({ err: true, message: "Incorrect Pin!" });
            }

            await usersCollection.updateOne({ email }, {
                $inc: {
                    balance: - amount
                }
            });

            await usersCollection.updateOne({ mobile: agent }, {
                $inc: {
                    balance: _amount + (_amount * (1 / 100)),
                    income: _amount * (1 / 100)
                }
            })

            await usersCollection.updateOne({ role: 1 }, {
                $inc: {
                    balance: _amount * (.5 / 100)
                }
            })

            const salt = bcrypt.genSaltSync(10);
            const date = Date.now();
            const trxId = bcrypt.hashSync(date.toString(), salt);
            const transaction = {
                type: 'cash-out',
                amount: _amount,
                charge,
                from: email,
                to: agent.email,
                date,
                trxId
            }

            const result = await transactionCollection.insertOne(transaction);

            res.send({ ...result, trxId });
        })

        // balance inquiry
        app.get("/balance", verifyToken, async (req, res) => {
            const email = req.user.email;
            const result = await usersCollection.findOne({ email }, {
                projection: {
                    balance: 1
                }
            });

            res.send(result)
        })

        // Save credentials in database after sign up
        app.post('/create-user', async (req, res) => {
            const data = req.body;
            const emailQuery = { email: data.email }
            const mobileQuery = { mobile: data.mobile }
            const nidQuery = { nid: data.nid }

            const emailRes = await usersCollection.findOne(emailQuery);
            if (emailRes) return res.send({ err: true, duplicateEmail: true })

            const mobileRes = await usersCollection.findOne(mobileQuery);
            if (mobileRes) return res.send({ err: true, duplicateMobile: true })

            const nidRes = await usersCollection.findOne(nidQuery);
            if (nidRes) return res.send({ err: true, duplicateNid: true })

            const isUser = data.ac_type === 'user';
            data.role = isUser ? 3 : 2;
            data.balance = isUser ? 40 : 100000;
            !isUser && (data.income = 0);

            data.status = isUser ? 'active' : 'pending';

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

            if (result.ac_type === 'agent' && result.status !== 'approved') {
                return res.send({ restricted: true, message: "Your account is under review" });
            }

            if (result.status === 'blocked') {
                return res.send({ restricted: true, message: "Your account is temporarily blocked!" });
            }

            delete result.pin;
            jwtInit(req, res).send(result);
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