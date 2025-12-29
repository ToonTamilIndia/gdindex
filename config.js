/*  ░██████╗░██████╗░██╗░░░░░░░░██╗░██████╗░░░░█████╗░██████╗░░██████╗░
    ██╔════╝░██╔══██╗██║░░░░░░░░██║██╔════╝░░░██╔══██╗██╔══██╗██╔════╝░
    ██║░░██╗░██║░░██║██║░░░░░░░░██║╚█████╗░░░░██║░░██║██████╔╝██║░░██╗░
    ██║░░╚██╗██║░░██║██║░░░██╗░░██║░╚═══██╗░░░██║░░██║██╔══██╗██║░░╚██╗
    ╚██████╔╝██████╔╝██║██╗╚█████╔╝██████╔╝██╗╚█████╔╝██║░░██║╚██████╔╝
    ░╚═════╝░╚═════╝░╚═╝╚═╝░╚════╝░╚═════╝░╚═╝░╚════╝░╚═╝░░╚═╝░╚═════╝░
                             v 2.3.0 - Modular
                        Mega.nz support & Dashboard 
    
*/

// Service Accounts Configuration
const serviceaccounts = [{}];
const randomserviceaccount = serviceaccounts[Math.floor(Math.random() * serviceaccounts.length)];

// Load balancing domains
const domains_for_dl = [''];
const domain_for_dl = domains_for_dl[Math.floor(Math.random() * domains_for_dl.length)];
const video_domains_for_dl = [''];
const video_domain_for_dl = video_domains_for_dl[Math.floor(Math.random() * video_domains_for_dl.length)];

// Blocked regions and ASN (empty arrays = no blocking)
const blocked_region = [];
const blocked_asn = [];

// Main Authentication Configuration
const authConfig = {
    "siteName": "",
    "client_id": "",
    "client_secret": "",
    "refresh_token": "",
    "service_account": false,
    "service_account_json": randomserviceaccount,
    "files_list_page_size": 50,
    "search_result_list_page_size": 50,
    "enable_cors_file_down": false,
    "enable_password_file_verify": true,
    "direct_link_protection": false,
    "lock_folders": false,
    "enable_auth0_com": false,
    "roots": [
        {
            "id": "root",
            "name": "", //gdrive name
            "protect_file_link": false,
            "auth": { "": "" }  // username:password for folder access
        },
        {
            "id": "", //shared drive or folder ID
            "name": "Public",
            "protect_file_link": false
        }
    ]
};

// Mega.nz Configuration
const megaConfig = {
    "enabled": true,
    "accounts": [
        // Add your Mega.nz accounts here
        { "email": "example@mail.com", "password": "examplepassword" } // Mega account
    ],
    "roots": [
        // Add Mega.nz folders to serve
        // Format: Use full link OR separate id and key
        { 
            "link": "https://mega.nz/folder/EXAMPLE#EXAMPLEKEY", // Mega folder link
            //"id": "EXAMPLE", // Mega folder ID (if not using link)
            //"key": "EXAMPLEKEY", // Mega folder key (if not using link) 
            "name": "MegaFolder", 
            "public": true 
        }
    ]
};

// Auth0 Configuration
const auth0Config = {
    domain: "",
    clientId: "",
    clientSecret: "",
    callbackUrl: "",
    logoutUrl: ""
};

// UI Configuration
const uiConfig = {
    "theme": "slate",
    "version": "2.2.3",
    "logo_image": true,
    "logo_height": "",
    "logo_width": "100px",
    "favicon": "https://cdn.jsdelivr.net/npm/@googledrive/index@2.2.3/images/favicon.ico",
    "logo_link_name": "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEih6RA7TbLUeKTDfQeoHF8z2-taWZ7ToOuVcPyCoXIPcznID14xeQuWJXksEOG_AlALUhAXWGzcrMik08s_V1DXBRmb5bpEUs0aO3nkfEKE2lkmuWi-Jo4vLyPI1mVDqQODsx34RD4TVXOMFtQDQen33qwLRnCMqHdOiAYC4tNBKv_fQN4XmY16DiWd/s922/Screenshot_2022-12-04-09-19-50-463-edit_com.camerasideas.trimmer.jpg",
    "fixed_header": true,
    "header_padding": "100",
    "nav_link_1": "Home",
    "nav_link_3": "Current Path",
    "nav_link_4": "Contact",
    "show_logout_button": false,
    "fixed_footer": false,
    "hide_footer": true,
    "header_style_class": "navbar-dark bg-primary",
    "footer_style_class": "bg-primary",
    "css_a_tag_color": "white",
    "css_p_tag_color": "white",
    "folder_text_color": "white",
    "loading_spinner_class": "text-light",
    "search_button_class": "btn btn-danger",
    "path_nav_alert_class": "alert alert-primary",
    "file_view_alert_class": "alert alert-danger",
    "file_count_alert_class": "alert alert-secondary",
    "contact_link": "https://telegram.dog/Toontamilind",
    "copyright_year": "2050",
    "company_name": "Toon Tamil India",
    "company_link": "https://telegram.dog/Toontamilind",
    "credit": true,
    "display_size": true,
    "display_time": false,
    "display_download": true,
    "disable_player": false,
    "custom_srt_lang": "",
    "disable_video_download": false,
    "second_domain_for_dl": false,
    "downloaddomain": domain_for_dl,
    "videodomain": video_domain_for_dl,
    "poster": "https://cdn.jsdelivr.net/npm/@googledrive/index@2.2.3/images/poster.jpg",
    "audioposter": "https://cdn.jsdelivr.net/npm/@googledrive/index@2.2.3/images/music.jpg",
    "jsdelivr_cdn_src": "https://cdn.jsdelivr.net/npm/@googledrive/index",
    "render_head_md": true,
    "render_readme_md": true,
    "display_drive_link": false,
    "plyr_io_version": "3.7.2",
    "plyr_io_video_resolution": "16:9",
    "unauthorized_owner_link": "https://telegram.dog/Toontamilindia",
    "unauthorized_owner_email": "toontamilind@gmail.com",
    "convert_search_to_google_drive_app": false
};

// Dashboard admin credentials
const dashboardConfig = {
    "admin_username": "admin",
    "admin_password": "admin123",
    "session_secret": "your-secret-key-here"
};

// Export all configurations
export {
    serviceaccounts,
    randomserviceaccount,
    domains_for_dl,
    domain_for_dl,
    video_domains_for_dl,
    video_domain_for_dl,
    blocked_region,
    blocked_asn,
    authConfig,
    megaConfig,
    auth0Config,
    uiConfig,
    dashboardConfig
};
