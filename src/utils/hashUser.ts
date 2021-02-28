import { IUser } from "../types";

import objectHash from "object-hash";

export const hashUser = (user: Partial<IUser>): string => {
    const hashData: Partial<IUser> = { ...user };

    if (
        !hashData.username ||
        !hashData.passwordHash ||
        !hashData.salt ||
        !hashData.address
    ) {
        throw new Error(
            "at least username, passwordhash, salt, and address are required"
        );
    }

    delete hashData.userID;
    delete hashData.userHash;

    return objectHash(hashData);
};
