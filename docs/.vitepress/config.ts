import { defineConfig } from "vitepress";
import { tabsMarkdownPlugin } from "vitepress-plugin-tabs";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "JWT",
  titleTemplate: "A-Novel Kit",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: "JWK", link: "/keys/index" },
      { text: "Producer", link: "/producer/index" },
      { text: "Recipient", link: "/recipient/index" },
    ],

    sidebar: [
      {
        text: "Json Web Keys",
        items: [
          { text: "Json Web Keys", link: "/keys/index" },
          { text: "Generate JWK", link: "/keys/generate" },
          {
            text: "Consume JWK",
            items: [
              { text: "Consume JWK", link: "/keys/consume/index" },
              { text: "JWK Source", link: "/keys/consume/source" },
            ],
          },
        ],
      },
      {
        text: "Producer",
        items: [
          { text: "Producer", link: "/producer/index" },
          { text: "Producer Customization", link: "/producer/customization" },
          { text: "Produce Signed Tokens", link: "/producer/signature" },
          {
            text: "Produce Encrypted Tokens",
            items: [
              { text: "Produce Encrypted Tokens", link: "/producer/encryption/index" },
              { text: "Direct Encryption", link: "/producer/encryption/direct" },
              { text: "Key Wrap", link: "/producer/encryption/key_wrap" },
              { text: "Key Agreement", link: "/producer/encryption/key_agreement" },
              { text: "Key Agreement With Key Wrap", link: "/producer/encryption/key_agreement_with_key_wrap" },
              { text: "Key Encryption With PBES2", link: "/producer/encryption/key_encryption_pbes2" },
              { text: "Key Encryption With RSA", link: "/producer/encryption/key_encryption_rsa" },
            ],
          },
        ],
      },
      {
        text: "Recipient",
        items: [
          { text: "Recipient", link: "/recipient/index" },
          { text: "Claims Check", link: "/recipient/claims_check" },
          { text: "Consume Signed Tokens", link: "/recipient/signature" },
          {
            text: "Produce Encrypted Tokens",
            items: [
              { text: "Consume Encrypted Tokens", link: "/recipient/encryption/index" },
              { text: "Direct Encryption", link: "/recipient/encryption/direct" },
              { text: "Key Wrap", link: "/recipient/encryption/key_wrap" },
              { text: "Key Agreement", link: "/recipient/encryption/key_agreement" },
              { text: "Key Agreement With Key Wrap", link: "/recipient/encryption/key_agreement_with_key_wrap" },
              { text: "Key Encryption With PBES2", link: "/recipient/encryption/key_encryption_pbes2" },
              { text: "Key Encryption With RSA", link: "/recipient/encryption/key_encryption_rsa" },
            ],
          },
        ],
      },
    ],

    socialLinks: [{ icon: "github", link: "https://github.com/a-novel-kit/jwt" }],
  },

  head: [["link", { rel: "icon", href: "./icon.png" }]],

  base: "/jwt/",

  markdown: {
    config(md) {
      md.use(tabsMarkdownPlugin);
    },
  },
});
