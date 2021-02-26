import axios from "axios";
import atob from "atob";
import { sleep } from "@extrahash/sleep";

const monitoredCurrencies = ["turtlecoin", "bitcoin", "ethereum"];

export class PriceScraper {
    private prices: Record<string, number> = {
        ethereum: 0,
        bitcoin: 0,
        turtlecoin: 0,
    };

    constructor() {
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
        for (const id in res.data) {
            this.prices[id] = res.data[id].usd;
        }
    }

    private async scrape() {
        while (true) {
            await this.getData(monitoredCurrencies);
            await sleep(30000);
        }
    }
}
