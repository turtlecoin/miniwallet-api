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
import expressWs from "express-ws";
import crypto from "crypto";
import { hashPassword } from "./utils/hashPassword";
import { IUser, SerializedTx } from "./types";
// tslint:disable-next-line: no-submodule-imports
import { Transaction } from "turtlecoin-wallet-backend/dist/lib/Types";
import { sleep } from "@extrahash/sleep";
import {
    validateAddress,
    validateAddresses,
    validatePaymentID,
    WalletError,
} from "turtlecoin-wallet-backend";
import rateLimit from "express-rate-limit";
import Speakeasy from "speakeasy";
import QRCode from "qrcode";
import { PriceScraper } from "./PriceScraper";
import axios from "axios";
import { hashUser } from "./utils/hashUser";
import * as uuid from "uuid";
import fs from "fs";
import WebSocket from "ws";
import path from "path";
import { deepEqual } from "assert";

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
});

loadEnv();
log.setLevel(process.env.LOG_LEVEL! as LogLevelDesc);

const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;

if (!fs.existsSync("qrs")) {
    fs.mkdirSync("qrs");
}

const checkAuth = (req: any, res: any, next: () => void) => {
    const token = req.cookies.auth;

    if (token) {
        try {
            const result = jwt.verify(token, process.env.SPK!);

            // lol glad this is a try/catch block
            (req as any).user = (result as any).user;
            (req as any).exp = (result as any).exp;
        } catch (err) {
            log.warn(err.toString());
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
    const expWs = expressWs(express());
    const app = expWs.app;
    const storage = await Storage.create();
    const wallet = await Wallet.getWallet();
    const priceScraper = new PriceScraper();

    const clients = new Map<string, { user: IUser; socket: WebSocket }>();

    const require2FA = async (req: any, res: any, next: () => void) => {
        if (!req.userEntry) {
            const userEntry = await storage.retrieveUser(
                (req as any).user.userID
            );
            if (!userEntry) {
                res.sendStatus(500);
                return;
            }
            req.userEntry = userEntry;
        }

        if (!req.user.twoFactor) {
            next();
            return;
        }

        const { totp, token }: { token: string; totp: string } = req.body;

        if (!totp && !token) {
            res.status(401).send("Invalid credentials.");
            return;
        }

        if (!req.userEntry.twoFactor) {
            next();
            return;
        }

        const valid = Speakeasy.time.verify({
            secret: req.userEntry.totpSecret,
            encoding: "base32",
            // TODO: clean this up in future versions, standardize
            token: totp || token,
            window: 2,
        });
        if (valid) {
            next();
        } else {
            res.status(401).send("Invalid credentials.");
            return;
        }
    };

    const requirePW = async (req: any, res: any, next: () => void) => {
        const { password } = req.body;

        if (!password && !req.body.oldPassword) {
            res.status(401).send("Invalid credentials.");
            return;
        }

        if (!req.userEntry) {
            const userEntry = await storage.retrieveUser(
                (req as any).user.userID
            );
            if (!userEntry) {
                res.status(401).send("Invalid credentials.");
                return;
            }
            req.userEntry = userEntry;
        }

        // for old change pw impementation, remember to remove after a couple versions
        const hash = await hashPassword(
            password || req.body.oldPassword,
            req.userEntry.salt
        );

        if (hash !== req.userEntry.passwordHash) {
            res.status(401).send("Invalid credentials.");
            return;
        }
        console.log("Password correct.");
        next();
    };

    const notify = (address: string, message: string) => {
        for (const [id, clientData] of clients.entries()) {
            if (clientData.user?.address == address) {
                clientData.socket.send(message);
            }
        }
    };

    const broadcast = (message: string) => {
        for (const [id, clientData] of clients.entries()) {
            clientData.socket.send(message);
        }
    };

    const safu = async () => {
        const allUsers = await storage.retrieveAllUsers();

        (async () => {
            // checking if all the keys are on the safu
            const res = await axios.post(
                process.env.KEYSTORE_HOST + "/keys/check",
                allUsers.map((user) => user.address)
            );
            const missingAddresses: string[] = res.data;
            for (const address of missingAddresses) {
                const [, spendKey] = await wallet
                    .getWallet()
                    .getSpendKeys(address);
                const viewKey = wallet.getWallet().getPrivateViewKey();
                try {
                    await axios.post(
                        process.env.KEYSTORE_HOST + "/keys/submit",
                        { address, spendKey, viewKey }
                    );
                } catch (err) {
                    log.warn("error storing key on safu");
                    log.warn(err.toString());
                }
            }
        })();

        (async () => {
            const userHashMap = new Map<string, string>();
            const userMap = new Map<number, IUser>();
            allUsers.forEach((user) => {
                // we have to use string as we are serializing it with Object.entries()
                userHashMap.set(user.userID.toString(), user.userHash);
                userMap.set(user.userID, user);
            });
            const res = await axios.post(
                process.env.KEYSTORE_HOST + "/users/check",
                Object.fromEntries(userHashMap)
            );
            const neededUsers: number[] = res.data;

            for (const userID of neededUsers) {
                await axios.post(
                    process.env.KEYSTORE_HOST + "/users/submit",
                    userMap.get(userID)
                );
            }
        })();
    };
    safu();

    const pending2FAKeys: Record<number, string> = {};

    priceScraper.on(
        "prices",
        (data: { bitcoin: number; ethereum: number; turtlecoin: number }) => {
            broadcast(JSON.stringify({ type: "prices", data }));
        }
    );

    wallet.on("transaction", (txMap: Map<string, Partial<SerializedTx>>) => {
        for (const [address, data] of txMap.entries()) {
            notify(address, JSON.stringify({ type: "transaction", data }));
        }
    });

    wallet.on("sync", (data: { wallet: number; daemon: number }) => {
        log.info(`Synced: ${data.wallet}/${data.daemon}`);
        broadcast(JSON.stringify({ type: "sync", data }));
    });

    app.use(express.json({ limit: "2mb" }));
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

    app.get("/wallet/sync", protect, async (req, res) => {
        res.send(wallet.getSyncData());
    });

    app.get("/qr/:address", protect, async (req, res) => {
        const { address } = req.params;
        fs.access("qrs/" + address, undefined, async (err) => {
            if (err) {
                console.log(err.toString());
                if (!validateAddress(address, true)) {
                    res.sendStatus(400);
                    return;
                }
                QRCode.toFile(
                    path.resolve(".", "./qrs/" + address),
                    address,
                    (err) => {
                        if (err) {
                            res.sendStatus(500);
                            return;
                        }
                        res.set("Cache-control", "public, max-age=31536000");
                        res.sendFile(path.resolve(".", "./qrs/" + address));
                    }
                );
            } else {
                res.set("Cache-control", "public, max-age=31536000");
                res.sendFile(path.resolve(".", "qrs/" + address));
            }
        });
    });

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
        res.send({ secret: secret.base32, qr: qr.toString("base64") });
        safu();
    });

    app.post(
        "/account/totp/disenroll",
        protect,
        requirePW,
        require2FA,
        async (req, res) => {
            const updates = {
                totpSecret: null,
                twoFactor: false,
            };
            await storage.updateUser((req as any).user.userID, updates);

            const newTokenData: Partial<IUser> = { ...(req as any).user };
            newTokenData.twoFactor = false;

            const token = jwt.sign({ user: newTokenData }, process.env.SPK!, {
                expiresIn: "1d",
            });
            res.cookie("auth", token);
            res.send(JSON.stringify(newTokenData));

            safu();
        }
    );

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
            res.status(401).send("Invalid credentials.");
        }
        safu();
    });

    app.post(
        "/account/password",
        protect,
        requirePW,
        require2FA,
        async (req, res) => {
            const { newPassword }: { newPassword: string } = req.body;

            const salt = crypto.randomBytes(24).toString("hex");
            const newHash = await hashPassword(newPassword, salt);

            await storage.updateUser((req as any).user.userID, {
                salt,
                passwordHash: newHash,
            });
            res.sendStatus(200);
            safu();
        }
    );

    app.post("/logout", protect, async (req, res) => {
        const user: Partial<IUser> = (req as any).user;
        const token = jwt.sign({ user }, process.env.SPK!, { expiresIn: -1 });
        res.cookie("auth", token);
        res.sendStatus(200);
    });

    app.post("/auth", limiter, async (req, res) => {
        const { username, password, totp } = req.body;

        if (!username || !password) {
            res.status(400).send("All fields are required.");
            return;
        }
        const user = await storage.retrieveUserByUsername(username);
        if (!user) {
            res.status(401).send("Invalid credentials.");
            return;
        }
        const hash = await hashPassword(password, user.salt);
        if (hash !== user.passwordHash) {
            res.status(401).send("Invalid credentials.");
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
                res.status(401).send("Invalid credentials.");
                return;
            }
        }

        const tokenData: Partial<IUser> = user;
        delete tokenData.passwordHash;
        delete tokenData.salt;
        delete tokenData.totpSecret;

        const token = jwt.sign({ user: tokenData }, process.env.SPK!, {
            expiresIn: user.twoFactor ? "7d" : "1d",
        });
        res.cookie("auth", token);
        res.send(JSON.stringify(tokenData));
    });

    app.get("/wallet/transactions", protect, async (req, res) => {
        const user: IUser = (req as any).user;
        const txs = await wallet.getTransactionHistory(user.address);
        res.send(txs);
    });

    app.get("/wallet/balance", protect, async (req, res) => {
        const address: string = (req as any).user.address;
        const balance = await wallet.getBalance(address);
        res.send(JSON.stringify(balance));
    });

    app.post(
        "/wallet/secrets",
        protect,
        requirePW,
        require2FA,
        limiter,
        async (req, res) => {
            const secrets = await wallet.getSecrets((req as any).user.address);
            res.send(JSON.stringify(secrets));
        }
    );

    app.post("/wallet/send", protect, require2FA, async (req, res) => {
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
        if (paymentID && validatePaymentID(paymentID).errorCode !== 0) {
            res.status(400).send("Invalid payment ID.");
            return;
        }
        if (paymentID && address.length === 187) {
            res.status(400).send(
                "Can't provide a payment ID with an integrated address."
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
                throw new Error("Couldn't retrieve sent transaction details.");
            }

            res.status(200).send(serializeTx(transaction));
        } catch (err) {
            log.error(err.toString());
            res.sendStatus(500);
            return;
        }
    });

    app.get("/price", protect, (req, res) => {
        res.send(JSON.stringify(priceScraper.getPrices()));
    });

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
            totpSecret: null,
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
            safu();
        } catch (err) {
            res.status(400).send("Username is already is taken.");
            log.warn(err.toString());
            return;
        }
    });

    app.ws("/socket", (ws, req) => {
        const user: IUser = (req as any).user;
        const clientID = uuid.v4();
        console.log("New client", clientID);

        let alive = true;
        let missedPings = 0;

        const heartbeat = () => {
            alive = true;
        };

        ws.on("message", (message) => {
            try {
                const msg = JSON.parse(message as string);
                const { type } = msg;
                switch (type) {
                    case "pong":
                        heartbeat();
                        break;
                    case "ping":
                        if (!alive) {
                            console.warn("Ping no response from " + clientID);
                            ws.terminate();
                            return;
                        }
                        alive = false;
                        ws.send(JSON.stringify({ type: "pong" }));
                        break;
                    default:
                        log.warn("Unsupported message type", type);
                        break;
                }
            } catch (err) {
                log.warn(err.toString());
            }
        });

        const pingInterval = setInterval(
            () => ws.send(JSON.stringify({ type: "ping" })),
            10000
        );
        ws.on("close", () => {
            clearInterval(pingInterval);
            console.log("Removing client", clientID);
            clients.delete(clientID);
        });

        clients.set(clientID, { user, socket: ws });
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
