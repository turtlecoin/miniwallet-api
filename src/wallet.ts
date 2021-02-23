import { EventEmitter } from "events";
import {
    createIntegratedAddress,
    Daemon,
    WalletBackend,
} from "turtlecoin-wallet-backend";
import fs from "fs";
import crypto from "crypto";
import log from "loglevel";

export class Wallet extends EventEmitter {
    private static instance: Wallet;

    public static getWallet = async () => {
        if (!Wallet.instance) {
            Wallet.instance = new Wallet();
            await Wallet.instance.init();
        }

        return Wallet.instance;
    };

    private daemon: Daemon;
    private wallet?: WalletBackend;

    private constructor() {
        super();
        this.daemon = new Daemon(
            process.env.DAEMON_URI!,
            Number(process.env.DAEMON_PORT!)
        );
    }

    public save() {
        this.wallet?.saveWalletToFile(
            process.env.WALLET_PATH!,
            process.env.WALLET_PASSWORD!
        );
    }

    public getWallet() {
        return this.wallet!;
    }

    public async createAddress(): Promise<{
        address: string;
        paymentID: string;
    }> {
        if (!this.wallet) {
            throw new Error("No wallet!");
        }

        const paymentID = crypto.randomBytes(32).toString("hex");
        const address = await createIntegratedAddress(
            this.wallet.getPrimaryAddress(),
            paymentID
        );
        return { address, paymentID };
    }

    private async init() {
        if (!fs.existsSync(process.env.WALLET_PATH!)) {
            console.log("Creating wallet file.");
            const newWallet = await WalletBackend.createWallet(this.daemon);
            newWallet.saveWalletToFile(
                process.env.WALLET_PATH!,
                process.env.WALLET_PASSWORD!
            );
        }

        const [wallet, err] = await WalletBackend.openWalletFromFile(
            this.daemon,
            process.env.WALLET_PATH!,
            process.env.WALLET_PASSWORD!
        );

        if (!wallet) {
            throw new Error(err?.toString());
        }

        wallet.on(
            "heightchange",
            (walletHeight, localHeight, networkHeight) => {
                console.log(`Sync: ${walletHeight}/${networkHeight}`);
            }
        );

        wallet.on("incomingtx", (transaction) => {
            log.info(
                `Incoming transaction of ${transaction.totalAmount()} to ${
                    transaction.paymentID
                }`
            );
            this.emit("incomingtx", transaction);
        });

        wallet.on("outgoingtx", (transaction) => {
            log.info(`Outgoing transaction of ${transaction.totalAmount()}`);
            this.emit("outgoingtx", transaction);
        });

        process.on("SIGINT", async () => {
            console.log("Shutting down wallet, please wait.");
            this.save();
            process.exit(0);
        });

        await wallet.start();
        log.info(`Started wallet, address ${wallet.getPrimaryAddress()}`);
        this.wallet = wallet;

        // await wallet.reset(3350000)
    }
}
