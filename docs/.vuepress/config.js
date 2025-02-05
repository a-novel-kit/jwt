import {viteBundler} from "@vuepress/bundler-vite";
import {markdownContainerPlugin} from "@vuepress/plugin-markdown-container";
import {defineUserConfig} from "vuepress";
import {hopeTheme} from "vuepress-theme-hope";

export default defineUserConfig({
    bundler: viteBundler({}),
    theme: hopeTheme({
        markdown: {
            tabs: true,
        },
        plugins: {},
        sidebar: [
            {
                text: "Home",
                link: "/",
                icon: "material-symbols:home-outline-rounded",
            },
            {
                text: "Consume tokens",
                link: "/recipient/",
                icon: "material-symbols:mark-as-unread-outline-rounded",
                collapsible: false,
                expanded: true,
                children: [
                    {
                        text: "Verify token (JWS)",
                        link: "/recipient/signature",
                        icon: "material-symbols:verified-outline-rounded",
                    },
                    {
                        text: "Decrypt token (JWE)",
                        link: "/recipient/encryption/",
                        icon: "material-symbols:lock-open-right-outline-rounded",
                        collapsible: true,
                        expanded: false,
                        children: [
                            {
                                text: "Direct Key Encryption",
                                link: "/recipient/encryption/direct",
                                icon: "material-symbols:share-outline",
                            },
                            {
                                text: "Key Wrapping",
                                link: "/recipient/encryption/key_wrap",
                                icon: "material-symbols:inventory-2-outline",
                            },
                            {
                                text: "Key Agreement",
                                link: "/recipient/encryption/key_agreement",
                                icon: "material-symbols:handshake-outline-rounded",
                            },
                            {
                                text: "Key Agr. with Key Wrap",
                                link: "/recipient/encryption/key_agreement_with_key_wrap",
                                icon: "material-symbols:encrypted-add-outline-rounded",
                            },
                            {
                                text: "Key Encryption (PBES2)",
                                link: "/recipient/encryption/key_encryption_pbes2",
                                icon: "material-symbols:password-rounded",
                            },
                            {
                                text: "Key Encryption (RSAES)",
                                link: "/recipient/encryption/key_encryption_rsa",
                                icon: "material-symbols:lock-open-circle-outline",
                            },
                        ],
                    },
                    {
                        text: "Claims check",
                        link: "/recipient/claims_check",
                        icon: "material-symbols:frame-inspect-rounded",
                    }
                ],
            },
            {
                text: "Produce tokens",
                link: "/producer/",
                icon: "material-symbols:edit-outline-rounded",
                collapsible: false,
                expanded: true,
                children: [
                    {
                        text: "Sign token (JWS)",
                        link: "/producer/signature",
                        icon: "material-symbols:security-key-outline",
                    },
                    {
                        text: "Encrypt token (JWE)",
                        link: "/producer/encryption/",
                        icon: "material-symbols:lock-outline",
                        collapsible: true,
                        expanded: false,
                        children: [
                            {
                                text: "Direct Key Encryption",
                                link: "/producer/encryption/direct",
                                icon: "material-symbols:share-outline",
                            },
                            {
                                text: "Key Wrapping",
                                link: "/producer/encryption/key_wrap",
                                icon: "material-symbols:inventory-2-outline",
                            },
                            {
                                text: "Key Agreement",
                                link: "/producer/encryption/key_agreement",
                                icon: "material-symbols:handshake-outline-rounded",
                            },
                            {
                                text: "Key Agr. with Key Wrap",
                                link: "/producer/encryption/key_agreement_with_key_wrap",
                                icon: "material-symbols:encrypted-add-outline-rounded",
                            },
                            {
                                text: "Key Encryption (PBES2)",
                                link: "/producer/encryption/key_encryption_pbes2",
                                icon: "material-symbols:password-rounded",
                            },
                            {
                                text: "Key Encryption (RSAES)",
                                link: "/producer/encryption/key_encryption_rsa",
                                icon: "material-symbols:lock-open-circle-outline",
                            },
                        ],
                    },
                    {
                        text: "Customization",
                        collapsible: true,
                        expanded: false,
                        link: "/producer/customization",
                        icon: "material-symbols:tune-rounded",
                    },
                ],
            },
            {
                text: "JSON Web Keys",
                link: "/keys/",
                icon: "material-symbols:key-outline-rounded",
                expanded: true,
                collapsible: false,
                children: [
                    {
                        text: "Consume JWK",
                        link: "/keys/consume/",
                        icon: "material-symbols:data-object-rounded",
                        expanded: false,
                        collapsible: true,
                        children: [
                            {
                                text: "JWK Source",
                                link: "/keys/consume/source",
                                icon: "material-symbols:stream-rounded",
                            },
                        ],
                    },
                    {
                        text: "Generate JWK",
                        link: "/keys/generate",
                        icon: "material-symbols:token-outline-rounded",
                    },
                ],
            },
        ],
    }),

    base: "/jwt/",

    plugins: [markdownContainerPlugin({})],

    lang: "en-US",
    title: "JWT - A-Novel Kit",
});
