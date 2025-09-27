import I18nKeys from "./src/locales/keys";
import type { Configuration } from "./src/types/config";

const YukinaConfig: Configuration = {
  title: "𝗯𝗹4𝗰𝗸0𝘂𝘁 blog",
  subTitle: "In the heart there is faith, under the feet there will be a path.",
  brandTitle: "𝗯𝗹4𝗰𝗸0𝘂𝘁",

  description: "In the heart there is faith, under the feet there will be a path.",

  site: "https://capt-bl4ck0ut.github.io",

  locale: "en", // set for website language and date format

  navigators: [
    {
      nameKey: I18nKeys.nav_bar_home,
      href: "/",
    },
    {
      nameKey: I18nKeys.nav_bar_archive,
      href: "/archive",
    },
    {
      nameKey: I18nKeys.nav_bar_about,
      href: "/about",
    },
    {
      nameKey: I18nKeys.nav_bar_github,
      href: "https://github.com/capt-bl4ck0ut",
    },
  ],

  username: "𝗯𝗹4𝗰𝗸0𝘂𝘁",
  sign: "Hack To Learn, Not Learn To Hack",
  avatarUrl: "https://vjz3r.github.io/_astro/avatar.BVI_3aoR_ZnA609.webp",
  socialLinks: [
    {
      icon: "line-md:github-loop",
      link: "https://github.com/capt-bl4ck0ut",
    },
    {
      icon: "line-md:discord",
      link: "https://discord.com/channels/@me",
    },
    {
      icon: "line-md:linkedin",
      link: "https://www.linkedin.com/in/vo-van-phuc/",
    },
    {
      icon: "line-md:facebook",
      link: "https://www.facebook.com/vanphuc233333?locale=vi_VN",
    },
  ],
  maxSidebarCategoryChip: 6, // It is recommended to set it to a common multiple of 2 and 3
  maxSidebarTagChip: 12,
  maxFooterCategoryChip: 6,
  maxFooterTagChip: 24,

  banners: [
    "https://vjz3r.github.io/_astro/banner.CPOmMyYa_ZqD4VL.webp",
    "https://66.media.tumblr.com/7d7916290ee905bba571911f6f168680/7450bd2ea56fb971-5a/s1280x1920/a51b66e5b81af9b2ccb3712c4ae929c23d7b0e19.gif",
    "https://i.gifer.com/embedded/download/758a.gif",
    "https://c.tenor.com/rePDfDWO3XoAAAAd/hacking.gif",
    "https://cdn.wallpapersafari.com/92/10/iHMTch.gif",
  ],

  slugMode: "HASH", // 'RAW' | 'HASH'

  license: {
    name: "CC BY-NC-SA 4.0",
    url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
  },

  // WIP functions
  bannerStyle: "LOOP", // 'loop' | 'static' | 'hidden'
};

export default YukinaConfig;
