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
import { IUser, SerializedTx } from "./types";
// tslint:disable-next-line: no-submodule-imports
import { Transaction } from "turtlecoin-wallet-backend/dist/lib/Types";
import { sleep } from "@extrahash/sleep";
import { validateAddress, validatePaymentID } from "turtlecoin-wallet-backend";
import rateLimit from "express-rate-limit";
import Speakeasy from "speakeasy";
import QRCode from "qrcode";

// tslint:disable-next-line: no-var-requires
const queue = require("express-queue");
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
});

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

const allowedOrigins = [
    "http://localhost:8080",
    "https://trtl.co.in",
    "https://www.trtl.co.in",
    "http://trtlcoinonqzucp3usix72kol3nkhrinobmnewdm5742bbqjfhgietid.onion",
    "http://www.trtlcoinonqzucp3usix72kol3nkhrinobmnewdm5742bbqjfhgietid.onion",
];
async function main() {
    const app = express();
    const storage = await Storage.create();
    const wallet = await Wallet.getWallet();

    const pending2FAKeys: Record<number, string> = {};

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
                    return callback(null, false);
                }
                return callback(null, true);
            },
        })
    );
    app.use(checkAuth);

    app.get("/account/totp/secret", protect, async (req, res) => {
        const secret = Speakeasy.generateSecret({
            length: 20,
            name: "miniwallet",
        });
        pending2FAKeys[(req as any).user.userID] = secret.base32;
        setTimeout(() => {
            if (pending2FAKeys[(req as any).user.userID] == secret.base32) {
                delete pending2FAKeys[(req as any).user.userID];
            }
        }, 1000 * 60 * 20);
        const qr = await QRCode.toBuffer(
            `otpauth://totp/Miniwallet:${(req as any).user.username}?secret=${
                secret.base32
            }`
        );
        console.log("Generated secret:", secret.base32);
        res.send({ secret: secret.base32, qr: qr.toString("base64") });
    });

    app.post("/account/totp/disenroll", protect, async (req, res) => {
        const { token, password } = req.body;
        const userEntry = await storage.retrieveUser((req as any).user.userID);
        if (!userEntry) {
            res.sendStatus(401);
            return;
        }
        if (!userEntry.totpSecret) {
            res.sendStatus(400);
            return;
        }
        const hash = await hashPassword(password, userEntry.salt);
        if (hash !== userEntry.passwordHash) {
            res.sendStatus(401);
            return;
        }

        const valid = Speakeasy.time.verify({
            secret: userEntry.totpSecret,
            encoding: "base32",
            token,
            window: 2,
        });
        if (valid) {
            const updates = {
                totpSecret: null,
                twoFactor: false,
            };
            await storage.updateUser(userEntry.userID, updates);

            const newTokenData: Partial<IUser> = { ...(req as any).user };
            newTokenData.twoFactor = false;

            const token = jwt.sign({ user: newTokenData }, process.env.SPK!, {
                expiresIn: "1d",
            });
            res.cookie("auth", token);
            res.send(JSON.stringify(newTokenData));
        } else {
            res.sendStatus(401);
        }
    });

    app.post("/account/totp/enroll", protect, async (req, res) => {
        if ((req as any).user.twoFactor) {
            res.status(400).send(
                "You already have 2FA enabled. Disable it first to set a new code."
            );
            return;
        }
        const secret = pending2FAKeys[(req as any).user.userID];
        const { token } = req.body;
        const user: IUser = (req as any).user;
        const valid = Speakeasy.time.verify({
            secret,
            encoding: "base32",
            token,
            window: 2,
        });
        if (valid) {
            const updates = {
                totpSecret: secret,
                twoFactor: true,
            };
            await storage.updateUser(user.userID, updates);
            const newTokenData: Partial<IUser> = { ...(req as any).user };
            newTokenData.twoFactor = true;
            const token = jwt.sign({ user: newTokenData }, process.env.SPK!, {
                expiresIn: "1d",
            });
            res.cookie("auth", token);
            res.send(JSON.stringify(newTokenData));
        } else {
            res.sendStatus(401);
        }
    });

    app.post("/account/password", protect, async (req, res) => {
        const {
            oldPassword,
            newPassword,
        }: { oldPassword: string; newPassword: string } = req.body;
        const user = await storage.retrieveUser((req as any).user.userID);
        if (!user) {
            res.sendStatus(401);
            return;
        }
        const hash = await hashPassword(oldPassword, user.salt);
        if (hash !== user.passwordHash) {
            res.sendStatus(401);
            return;
        }
        const salt = crypto.randomBytes(24).toString("hex");
        const newHash = await hashPassword(newPassword, salt);

        await storage.updateUser((req as any).user.userID, {
            salt,
            passwordHash: newHash,
        });
        res.sendStatus(200);
    });

    app.post("/logout", protect, async (req, res) => {
        const user: Partial<IUser> = (req as any).user;
        const token = jwt.sign({ user }, process.env.SPK!, { expiresIn: -1 });
        res.cookie("auth", token);
        res.sendStatus(200);
    });

    app.post("/auth", limiter, async (req, res) => {
        console.log(req.body);
        const { username, password, totp } = req.body;

        if (!username || !password) {
            res.status(400).send("All fields are required.");
            return;
        }
        const user = await storage.retrieveUserByUsername(username);
        if (!user) {
            res.sendStatus(401);
            return;
        }
        const hash = await hashPassword(password, user.salt);
        if (hash !== user.passwordHash) {
            res.sendStatus(401);
            return;
        }

        if (user.twoFactor) {
            if (!totp) {
                res.sendStatus(202);
                return;
            }
            if (!user.totpSecret) {
                res.sendStatus(500);
                return;
            }
            const valid = Speakeasy.time.verify({
                secret: user.totpSecret,
                encoding: "base32",
                token: totp,
                window: 2,
            });
            if (!valid) {
                res.sendStatus(403);
                return;
            }
        }

        const tokenData: Partial<IUser> = user;
        delete tokenData.passwordHash;
        delete tokenData.salt;
        delete tokenData.totpSecret;

        const token = jwt.sign({ user: tokenData }, process.env.SPK!, {
            expiresIn: "1d",
        });
        res.cookie("auth", token);
        res.send(JSON.stringify(tokenData));
    });

    app.get("/wallet/transactions", protect, async (req, res) => {
        const user: IUser = (req as any).user;
        const txs = await wallet.getTransactionHistory(
            (req as any).user.address
        );
        res.send(txs);
    });

    app.get("/wallet/balance", protect, async (req, res) => {
        const address: string = (req as any).user.address;
        const balance = await wallet.getBalance(address);
        res.send(JSON.stringify(balance));
    });

    app.post("/wallet/secrets", protect, limiter, async (req, res) => {
        const { password } = req.body;
        const user = await storage.retrieveUser((req as any).user.userID);
        if (!user) {
            res.sendStatus(500);
            return;
        }
        const hash = await hashPassword(password, user.salt);
        if (hash !== user.passwordHash) {
            res.sendStatus(401);
            return;
        }

        const secrets = await wallet.getSecrets((req as any).user.address);
        res.send(JSON.stringify(secrets));
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
            const balance = await wallet.getBalance((req as any).user.address);
            if (balance.unlocked < amount) {
                res.status(400).send("Insufficient funds in the account.");
                return;
            }

            try {
                const result = await wallet.sendTransaction(
                    (req as any).user.address,
                    address,
                    amount,
                    paymentID
                );

                if (!result.success) {
                    throw new Error("Transaction creation failure.");
                }
                const transaction = await wallet
                    .getWallet()
                    .getTransaction(result.transactionHash!);
                if (!transaction) {
                    throw new Error(
                        "Couldn't retrieve sent transaction details."
                    );
                }

                res.status(200).send(serializeTx(transaction));
            } catch (err) {
                log.error(err.toString());
                res.sendStatus(500);
                return;
            }
        }
    );

    app.get("/whoami", (req, res) => {
        const user: IUser | null = (req as any).user;
        if (!user) {
            res.sendStatus(204);
            return;
        }
        res.send(JSON.stringify(user));
    });

    app.post("/register", limiter, async (req, res) => {
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
        const { address } = await wallet.createAddress();

        const user: Partial<IUser> = {
            username,
            passwordHash: hash,
            salt,
            address,
            twoFactor: false,
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
}

main();

export const serializeTx = (
    transaction: Transaction
): Partial<SerializedTx> => {
    return {
        blockHeight: transaction.blockHeight,
        fee: transaction.fee,
        hash: transaction.hash,
        paymentID: transaction.paymentID,
        timestamp: transaction.timestamp,
        unlockTime: transaction.unlockTime,
        amount: transaction.totalAmount(),
    };
};
