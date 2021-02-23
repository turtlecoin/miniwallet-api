import log, { LogLevelDesc } from "loglevel";
import { loadEnv } from "./utils/loadEnv";
import express from "express";
import morgan from "morgan";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { Storage } from "./storage";
import { Wallet } from "./wallet";
import crypto from "crypto";
import { hashPassword } from "./utils/hashPassword";
import { IUser, SavedTransaction } from "./types";
// tslint:disable-next-line: no-submodule-imports
import { Transaction } from "turtlecoin-wallet-backend/dist/lib/Types";
import { sleep } from "@extrahash/sleep";
import { validateAddress, validatePaymentID } from "turtlecoin-wallet-backend";

// tslint:disable-next-line: no-var-requires
const queue = require("express-queue");

loadEnv();
log.setLevel(process.env.LOG_LEVEL! as LogLevelDesc);

const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;

const checkAuth = (req: any, res: any, next: () => void) => {
    const token = req.cookies.auth;

    if (token) {
        try {
            const result = jwt.verify(token, process.env.SPK!);

            // lol glad this is a try/catch block
            (req as any).user = (result as any).user;
            (req as any).exp = (result as any).exp;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

export const protect = (req: any, res: any, next: () => void) => {
    if (!req.user) {
        res.sendStatus(401);
        throw new Error("not authenticated!");
    }

    next();
};

const allowedOrigins = ["http://localhost:8080", "http://10.0.0.22:8080"];
async function main() {
    const app = express();
    const storage = await Storage.create();
    const wallet = await Wallet.getWallet();

    const depositWorker = async () => {
        while (true) {
            console.log("Getting deposit work.");
            const work = await storage.getDepositWork();
            const [, localHeight] = await wallet.getWallet().getSyncStatus();
            for (const deposit of work) {
                const transaction = await wallet
                    .getWallet()
                    .getTransaction(deposit.hash);
                if (!transaction) {
                    log.warn("Transaction not found.");
                    continue;
                }
                const confirmedBlock = localHeight - 120;
                if (transaction.blockHeight < confirmedBlock) {
                    log.info(`${transaction.hash} CONFIRMED`);
                    await storage.markTransactionAvailable(transaction.hash);
                } else {
                    log.info(
                        `${transaction.hash} ${
                            transaction.blockHeight - confirmedBlock
                        }/120 CONFIRMS`
                    );
                }
            }
            await sleep(30000);
        }
    };

    wallet.on("incomingtx", async (transaction: Transaction) => {
        log.info("Saving transaction.");
        if (transaction.paymentID) {
            const user = await storage.retrieveUserByPID(transaction.paymentID);
            if (!user) {
                console.warn("No user for PID.");
                return;
            }
            storage.createTransaction(serializeTx(transaction, user.userID));
        }
    });

    wallet.on("outgoingtx", (transaction: Transaction) => {
        log.info("Updating outgoing tx.");
        storage.updateTransaction(serializeTx(transaction));
    });

    app.use(express.json({ limit: "256kb" }));
    app.use(cookieParser());
    app.use(morgan("dev"));
    app.use(helmet());
    app.use(
        cors({
            credentials: true,
            origin: (origin, callback) => {
                if (!origin) {
                    return callback(null, true);
                }
                if (!allowedOrigins.includes(origin)) {
                    return callback(new Error("Invalid origin."), false);
                }
                return callback(null, true);
            },
        })
    );
    app.use(checkAuth);

    app.post("/logout", protect, async (req, res) => {
        const user: Partial<IUser> = (req as any).user;
        const token = jwt.sign({ user }, process.env.SPK!, { expiresIn: -1 });
        res.cookie("auth", token);
        res.sendStatus(200);
    });

    app.post("/auth", async (req, res) => {
        const { username, password } = req.body;

        if (!username || !password) {
            res.sendStatus(400);
            return;
        }

        const user = await storage.retrieveUserByUsername(username);
        if (!user) {
            res.status(401);
            return;
        }

        const hash = await hashPassword(password, user.salt);
        if (hash !== user.passwordHash) {
            res.sendStatus(401);
            return;
        }

        const tokenData: Partial<IUser> = user;
        delete tokenData.passwordHash;
        delete tokenData.salt;

        const token = jwt.sign({ user: tokenData }, process.env.SPK!, {
            expiresIn: "1d",
        });
        res.cookie("auth", token);
        res.send(JSON.stringify(tokenData));
    });

    app.get("/wallet/transactions", protect, async (req, res) => {
        const user: IUser = (req as any).user;

        console.log(user);
        const txs = await storage.retrieveTransactions(
            (req as any).user.userID
        );
        res.send(txs);
    });

    app.get("/wallet/balance", protect, async (req, res) => {
        const paymentID: string = (req as any).user.paymentID;
        const balance = await storage.retrieveBalance(paymentID);
        res.send(JSON.stringify(balance));
    });

    app.post(
        "/wallet/send",
        protect,
        queue({ activeLimit: 1 }),
        async (req, res) => {
            const { amount, address, paymentID } = req.body as {
                amount: number;
                address: string;
                paymentID?: string;
            };
            console.log(amount);
            if (!Number.isInteger(amount)) {
                res.status(400).send("Invalid amount.");
                return;
            }
            if (amount <= 0) {
                res.status(400).send("Must be positive amount.");
            }
            if (!(await validateAddress(address, true))) {
                res.status(400).send("Invalid TRTL address.");
                return;
            }
            if (paymentID && validatePaymentID(paymentID)) {
                res.status(400).send("Invalid payment ID.");
                return;
            }
            if (paymentID && address.length === 187) {
                res.status(400).send(
                    "Can't provide both payment ID and address."
                );
                return;
            }
            const balance = await storage.retrieveBalance(
                (req as any).user.paymentID
            );
            if (balance.available < amount) {
                res.status(400).send("Insufficient funds in the account.");
                return;
            }

            try {
                const result = await wallet
                    .getWallet()
                    .sendTransactionBasic(address, amount, paymentID);
                if (result.success) {
                    const transaction: Partial<SavedTransaction> = {
                        fee: result.fee!,
                        hash: result.transactionHash!,
                        paymentID: paymentID!,
                        available: true,
                        amount: amount * -1 - result.fee!,
                        userID: (req as any).user.userID,
                    };
                    await storage.createTransaction(transaction);
                    res.send(transaction);
                    return;
                } else {
                    res.sendStatus(400);
                    return;
                }
            } catch (err) {
                console.log(err.toString());
                res.sendStatus(500);
                return;
            }
        }
    );

    app.get("/whoami", protect, (req, res) => {
        res.send(JSON.stringify((req as any).user));
    });

    app.post("/register", async (req, res) => {
        const { username, password } = req.body;

        if (!usernameRegex.test(username)) {
            res.status(400).send(
                "Invalid username. Only 3-20 length alphanumeric and underscore usernames allowed."
            );
            return;
        }

        if (password.length < 8) {
            res.status(400).send("Password must be of at least length 8.");
            return;
        }

        const salt = crypto.randomBytes(24).toString("hex");
        const hash = await hashPassword(password, salt);
        const { address, paymentID } = await wallet.createAddress();

        const user: Partial<IUser> = {
            username,
            passwordHash: hash,
            salt,
            address,
            paymentID,
        };

        try {
            const newUser = await storage.createUser(user);

            const tokenData: Partial<IUser> = { ...newUser };
            delete tokenData.passwordHash;
            delete tokenData.salt;

            const token = jwt.sign({ user: tokenData }, process.env.SPK!, {
                expiresIn: "1d",
            });
            res.cookie("auth", token);
            res.send(JSON.stringify(tokenData));
        } catch (err) {
            res.status(400).send("Username is already is taken.");
            console.warn(err.toString());
            return;
        }
    });

    app.listen(Number(process.env.PORT!), () => {
        log.info(`API started on port ${process.env.PORT}`);
    });

    depositWorker();
}

main();

const serializeTx = (
    transaction: Transaction,
    userID?: number
): Partial<SavedTransaction> => {
    return {
        blockHeight: transaction.blockHeight,
        fee: transaction.fee,
        hash: transaction.hash,
        paymentID: transaction.paymentID,
        timestamp: transaction.timestamp,
        unlockTime: transaction.unlockTime,
        amount: transaction.totalAmount(),
        userID,
    };
};
