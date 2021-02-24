import { EventEmitter } from "events";
import { Daemon, WalletBackend } from "turtlecoin-wallet-backend";
import fs from "fs";
import crypto from "crypto";
import log from "loglevel";
import { serializeTx } from ".";
import { SerializedTx } from "./types";
// tslint:disable-next-line: no-submodule-imports
import { SendTransactionResult } from "turtlecoin-wallet-backend/dist/lib/Types";

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
        this.getWallet().saveWalletToFile(
            process.env.WALLET_PATH!,
            process.env.WALLET_PASSWORD!
        );
    }

    public getWallet() {
        if (!this.wallet) {
            throw new Error("No wallet!");
        }

        return this.wallet;
    }

    public async getSecrets(
        address: string
    ): Promise<{
        spendKey: string;
        viewKey: string;
    }> {
        const [, spendKey] = await this.getWallet().getSpendKeys(address);
        if (!spendKey) {
            throw new Error("Can't get spendkey!");
        }

        const keys = {
            spendKey,
            viewKey: await this.getWallet().getPrivateViewKey(),
        };
        return keys;
    }

    public async sendTransaction(
        sendFrom: string,
        sendTo: string,
        amount: number,
        paymentID?: string
    ): Promise<SendTransactionResult> {
        return this.getWallet().sendTransactionAdvanced(
            [[sendTo, amount]],
            undefined,
            undefined,
            paymentID,
            [sendFrom],
            sendFrom
        );
    }

    public async createAddress(): Promise<{
        address: string;
    }> {
        const [address, err] = await this.getWallet().addSubWallet();
        if (err || !address) {
            throw new Error(err?.toString() || "Problem creating subwallet.");
        }
        this.save();
        return { address };
    }

    public async getTransactionHistory(
        address: string,
        offset = 0
    ): Promise<Partial<SerializedTx>[]> {
        const txs = await this.getWallet().getTransactions(
            offset,
            20,
            false,
            address
        );
        return txs.map((tx) => serializeTx(tx));
    }

    public async getBalance(
        address: string
    ): Promise<{ unlocked: number; locked: number }> {
        const [unlocked, locked] = (await this.getWallet().getBalance([
            address,
        ])) as number[];
        return { unlocked, locked };
    }

    private async init() {
        if (!fs.existsSync(process.env.WALLET_PATH!)) {
            log.info("Creating wallet file.");
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
                console.log({ walletHeight, localHeight, networkHeight });
            }
        );

        wallet.on("sync", () => {
            log.info("Wallet is synchronized.");
        });

        wallet.on("desync", () => {
            log.info("Wallet is desynchronized.");
        });

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
            log.info("Shutting down wallet, please wait.");
            this.save();
            process.exit(0);
        });

        await wallet.start();
        log.info(`Started wallet, address ${wallet.getPrimaryAddress()}`);

        this.wallet = wallet;
    }
}
