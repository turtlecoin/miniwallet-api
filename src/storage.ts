import { EventEmitter } from "events";
import knex from "knex";
import log from "loglevel";
import { IUser, SerializedTx } from "./types";

/**
 * The default IStorage() implementation, using knex and sqlite3 driver
 *
 * @hidden
 */
export class Storage extends EventEmitter {
    private dbPath: string;
    public db: knex<any, unknown[]>;

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
        log.info("Closing database.");
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

    public async updateUser(
        userID: number,
        user: Partial<IUser>
    ): Promise<void> {
        await this.db("users").update(user).where({ userID });
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

    public async init() {
        console.info("Initializing database.");
        try {
            if (!(await this.db.schema.hasTable("users"))) {
                await this.db.schema.createTable("users", (table) => {
                    table.increments("userID");
                    table.string("username").unique();
                    table.string("passwordHash").unique();
                    table.string("salt").unique();
                    table.string("address").unique().index();
                    table.boolean("2fa");
                    table.string("totpSecret");
                });
            }

            this.emit("ready");
        } catch (err) {
            this.emit("error", err);
        }
    }
}
