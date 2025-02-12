/**
 * @see https://prettier.io/docs/en/configuration.html
 * @type {import("prettier").Config}
 */
const config = {
    trailingComma: "es5",
    tabWidth: 2,
    semi: true,
    singleQuote: false,
    printWidth: 120,
    importOrder: [
        "^(.*).(css|yaml|json)$",
        "^(.*).(svg|png|jpg|jpeg)$",
        "^react(/(.*))?$",
        "<THIRD_PARTY_MODULES>",
        "^~/",
        "^[./]",
    ],
    importOrderSeparation: true,
    plugins: ["@trivago/prettier-plugin-sort-imports"],
};

export default config;
