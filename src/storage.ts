import { EventEmitter } from "events";
import knex from "knex";
import log from "loglevel";
import { IUser, SerializedTx } from "./types";
import { hashUser } from "./utils/hashUser";

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
        const newUser = { ...user };
        newUser.userHash = hashUser(newUser);
        const inserted = await this.db("users").insert(newUser);
        return (await this.retrieveUser(inserted[0]))!;
    }

    public async retrieveAllUsers(): Promise<IUser[]> {
        return (await this.db("users").select()).map((user: IUser) => {
            user.twoFactor = Boolean(user.twoFactor);
            return user;
        });
    }

    public async retrieveUser(userID: number): Promise<IUser | null> {
        const rows: IUser[] = await this.db("users").select().where({ userID });
        if (rows.length === 0) {
            return null;
        }
        rows[0].twoFactor = Boolean(rows[0].twoFactor);
        return rows[0];
    }

    public async retrieveUserByUsername(
        username: string
    ): Promise<IUser | null> {
        const rows = await this.db("users").select().where({ username });
        if (rows.length === 0) {
            return null;
        }
        rows[0].twoFactor = Boolean(rows[0].twoFactor);
        return rows[0];
    }

    public async updateUserHash(userID: number) {
        const user = await this.retrieveUser(userID);
        if (!user) {
            throw new Error("Couldn't find user!");
        }

        const userHash = hashUser(user);
        if (userHash !== user.userHash) {
            await this.updateUser(user.userID, { userHash });
        }
    }

    public async updateUser(
        userID: number,
        user: Partial<IUser>
    ): Promise<void> {
        await this.db("users").update(user).where({ userID });
        await this.updateUserHash(userID);
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
                    table.boolean("twoFactor");
                    table.string("totpSecret");
                    table.string("userHash");
                });
            }

            this.emit("ready");
        } catch (err) {
            this.emit("error", err);
        }
    }
}
