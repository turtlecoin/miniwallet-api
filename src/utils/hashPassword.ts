import { pbkdf2 } from "pbkdf2";

export const hashPassword = async (
    password: string,
    salt: string
): Promise<string> => {
    return new Promise((res, rej) => {
        pbkdf2(password, salt, 2000, 32, "sha512", (err, derivedKey) => {
            if (err) {
                rej(err);
            } else {
                res(derivedKey.toString("hex"));
            }
        });
    });
};
