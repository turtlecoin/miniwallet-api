import { EventEmitter } from "events";
import knex from "knex";
import { IUser, SavedTransaction } from "./types";

/**
 * The default IStorage() implementation, using knex and sqlite3 driver
 *
 * @hidden
 */
export class Storage extends EventEmitter {
    private dbPath: string;
    private db: knex<any, unknown[]>;

    public static async create() {
        const storage = new Storage();
        await storage.init();
        return storage;
    }

    private constructor() {
        super();

        this.dbPath = "db.sqlite";
        this.db = knex({
            client: "sqlite3",
            connection: {
                filename: this.dbPath,
            },
            useNullAsDefault: true,
        });
    }

    public async close(): Promise<void> {
        console.log("Closing database.");
        await this.db.destroy();
    }

    public async createUser(user: Partial<IUser>): Promise<IUser> {
        const inserted = await this.db("users").insert(user);

        const completedUser = { ...user };
        completedUser.userID = inserted[0];

        return completedUser as IUser;
    }

    public async retrieveUser(userID: number): Promise<IUser | null> {
        const rows = await this.db("users").select().where({ userID });
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async retrieveUserByPID(paymentID: string): Promise<IUser | null> {
        const rows = await this.db("users")
            .select()
            .where({ paymentID })
            .orWhere({});
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async getDepositWork(): Promise<SavedTransaction[]> {
        return this.db
            .from("transactions")
            .select()
            .where({ available: false });
    }

    public async markTransactionAvailable(hash: string) {
        await this.db("transactions")
            .update({ available: true })
            .where({ hash });
    }

    public async retrieveTransactions(
        userID: number
    ): Promise<SavedTransaction[]> {
        return this.db("transactions")
            .select()
            .where({ userID })
            .orderBy("transactionID", "desc");
    }

    public async retrieveUserByUsername(
        username: string
    ): Promise<IUser | null> {
        const rows = await this.db("users").select().where({ username });
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async createTransaction(
        transaction: Partial<SavedTransaction>
    ): Promise<void> {
        await this.db("transactions").insert(transaction);
    }

    public async updateTransaction(
        transaction: Partial<SavedTransaction>
    ): Promise<void> {
        await this.db("transactions")
            .update(transaction)
            .where({ hash: transaction.hash });
    }

    public async retrieveBalance(
        paymentID: string
    ): Promise<{ total: number; available: number }> {
        const user = await this.retrieveUserByPID(paymentID);
        if (!user) {
            throw new Error("Couldn't find user!");
        }

        const rows: SavedTransaction[] = await this.db("transactions")
            .select()
            .where({ userID: user.userID });
        const balance = {
            total: 0,
            available: 0,
        };

        for (const row of rows) {
            balance.total += row.amount;
            if (row.available) {
                balance.available += row.amount;
            }
        }

        return balance;
    }

    public async init() {
        console.info("Initializing database.");
        try {
            if (!(await this.db.schema.hasTable("users"))) {
                await this.db.schema.createTable("users", (table) => {
                    table.increments("userID");
                    table.string("username").unique();
                    table.string("passwordHash").unique();
                    table.string("salt").unique();
                    table.string("address");
                    table.string("paymentID").unique().index();
                });
            }

            if (!(await this.db.schema.hasTable("transactions"))) {
                await this.db.schema.createTable("transactions", (table) => {
                    table.increments("transactionID");
                    table.integer("userID").index();
                    table.integer("blockHeight");
                    table.integer("fee");
                    table.string("hash").unique().index();
                    table.string("paymentID").index();
                    table.integer("timestamp");
                    table.integer("unlockTime");
                    table.bigInteger("amount");
                    table.boolean("available").defaultTo(false);
                });
            }

            this.emit("ready");
        } catch (err) {
            this.emit("error", err);
        }
    }
}
