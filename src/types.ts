export interface IUser {
    userID: number;
    username: string;
    passwordHash: string;
    salt: string;
    address: string;
    paymentID: string;
}

export interface SavedTransaction {
    transactionID: number;
    userID: number;
    blockHeight: number;
    fee: number;
    hash: string;
    paymentID: string;
    timestamp: number;
    unlockTime: number;
    amount: number;
    available: boolean;
}
