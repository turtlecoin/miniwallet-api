import axios from "axios";
import atob from "atob";
import { sleep } from "@extrahash/sleep";
import { EventEmitter } from "events";

const monitoredCurrencies = ["turtlecoin", "bitcoin", "ethereum"];

export class PriceScraper extends EventEmitter {
    private prices: Record<string, number> = {
        ethereum: 0,
        bitcoin: 0,
        turtlecoin: 0,
    };

    constructor() {
        super();
        this.scrape();
    }

    public getPrices() {
        return this.prices;
    }

    private async getData(ids: string[]) {
        const res = await axios.get(
            `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(
                ids.join(",")
            )}&vs_currencies=usd`
        );
        let diff = false;
        for (const id in res.data) {
            if (this.prices[id] != res.data[id].usd) {
                this.prices[id] = res.data[id].usd;
                diff = true;
            }
        }
        if (diff) {
            this.emit("prices", this.prices);
        }
    }

    private async scrape() {
        while (true) {
            await this.getData(monitoredCurrencies);
            await sleep(10000);
        }
    }
}
