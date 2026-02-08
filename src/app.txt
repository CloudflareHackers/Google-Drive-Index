// Redesigned by telegram.dog/TheFirstSpeedster at https://www.npmjs.com/package/@googledrive/index which was written by someone else, credits are given on Source Page.
// v2.3.7

// ============================================================================
// FILE TYPE CONSTANTS - Centralized file extension mappings
// ============================================================================
const FILE_TYPES = {
    video: ['mp4', 'webm', 'avi', 'mpg', 'mpeg', 'mkv', 'rm', 'rmvb', 'mov', 'wmv', 'asf', 'ts', 'flv', '3gp', 'm4v'],
    audio: ['mp3', 'flac', 'wav', 'ogg', 'm4a', 'aac', 'wma', 'alac'],
    image: ['bmp', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'tiff', 'ico'],
    code: ['php', 'css', 'go', 'java', 'js', 'json', 'txt', 'sh', 'md', 'html', 'xml', 'py', 'rb', 'c', 'cpp', 'h', 'hpp'],
    archive: ['zip', 'rar', 'tar', '7z', 'gz'],
    document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
    markdown: ['md']
};

// ============================================================================
// HELPER FUNCTIONS - Reusable utilities
// ============================================================================

/**
 * Check if a file extension belongs to a specific type
 * @param {string} ext - File extension
 * @param {string} type - Type name from FILE_TYPES
 * @returns {boolean}
 */
function isFileType(ext, type) {
    return FILE_TYPES[type] && FILE_TYPES[type].includes(ext?.toLowerCase());
}

/**
 * Get the icon for a file based on its extension
 * @param {string} ext - File extension
 * @returns {string} - SVG icon HTML
 */
function getFileIcon(ext) {
    const extLower = ext?.toLowerCase();
    if (isFileType(extLower, 'video')) return video_icon;
    if (isFileType(extLower, 'audio')) return audio_icon;
    if (isFileType(extLower, 'image')) return image_icon;
    if (isFileType(extLower, 'code')) return code_icon;
    if (isFileType(extLower, 'archive')) return zip_icon;
    if (isFileType(extLower, 'markdown')) return markdown_icon;
    if (extLower === 'pdf') return pdf_icon;
    return file_icon;
}

/**
 * Generate breadcrumb navigation HTML for file views
 * @param {string} path - Current URL path
 * @param {boolean} isViewPage - Whether this is a file view page
 * @returns {string} - HTML for breadcrumb navigation
 */
function generateBreadcrumb(path, isViewPage = true) {
    const pathParts = path.split('/');
    let navigation = '';
    let newPath = '';
    
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (isViewPage && i === pathParts.length - 1) {
            newPath += part + '?a=view';
        } else {
            newPath += part + '/';
        }
        
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        
        if (part === '') {
            part = 'Home';
        }
        
        navigation += '<a href="' + newPath + '" class="breadcrumb-item">' + part + '</a>';
    }
    
    return navigation;
}

/**
 * Generate download button dropdown with various app integrations
 * @param {string} url - Download URL
 * @param {string} encodedName - URL-encoded filename
 * @param {boolean} isVideo - Whether this is a video file
 * @returns {string} - HTML for dropdown menu
 */
function generateDownloadDropdown(url, encodedName, isVideo = false) {
    let dropdown = '';
    
    if (isVideo) {
        dropdown += `
            <a class="dropdown-item" href="iina://weblink?url=${url}">IINA</a>
            <a class="dropdown-item" href="potplayer://${url}">PotPlayer</a>
            <a class="dropdown-item" href="vlc://${url}">VLC Mobile</a>
            <a class="dropdown-item" href="${url}">VLC Desktop</a>
            <a class="dropdown-item" href="nplayer-${url}">nPlayer</a>
            <a class="dropdown-item" href="intent://${url}#Intent;type=video/any;package=is.xyz.mpv;scheme=https;end;">mpv-android</a>
            <a class="dropdown-item" href="mpv://${btoa(url)}">mpv x64</a>
            <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.ad;S.title=${encodedName};end">MX Player (Free)</a>
            <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.pro;S.title=${encodedName};end">MX Player (Pro)</a>`;
    }
    
    dropdown += `
        <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encodedName};end">1DM (Free)</a>
        <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encodedName};end">1DM (Lite)</a>
        <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encodedName};end">1DM+ (Plus)</a>`;
    
    return dropdown;
}

/**
 * Create a standard file view container with card layout
 * @param {Object} options - Configuration object
 * @returns {string} - HTML content
 */
function createFileViewContainer(options) {
    const { name, size, url, encodedName, navigation, bodyContent = '', isVideo = false, showDownload = true } = options;
    
    const downloadSection = showDownload ? `
        <div class="card-body">
            <div class="input-group mb-4">
                <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
            </div>
            <div class="card-text text-center">
                <div class="btn-group text-center">
                    <a href="${url}" type="button" class="btn btn-primary">Download</a>
                    <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <span class="sr-only"></span>
                    </button>
                    <div class="dropdown-menu">
                        ${generateDownloadDropdown(url, encodedName, isVideo)}
                    </div>
                </div>
            </div>
            <br>
        </div>` : '';
    
    return `
        <div class="container text-center"><br>
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb">${navigation}</ol>
            </nav>
            <div class="card text-center">
                <div class="card-body text-center">
                    <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
                </div>
                ${bodyContent}
                ${downloadSection}
            </div>
        </div>`;
}

// ============================================================================
// MAIN APPLICATION CODE
// ============================================================================

// Initialize the page
function init() {
    document.siteName = $('title').html();
    const html = `<header>
   <div id="nav">
   </div>
</header>
<div class="loading" id="spinner" style="display:none;">Loading&#8230;</div>
<div>
<div id="content" style="padding-top: ${UI.header_padding}px;${UI.fixed_footer ?' padding-bottom: clamp(170px, 100%, 300px);': ''}">
</div>
<div class="modal fade" id="SearchModel" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="SearchModelLabel" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="SearchModelLabel"></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">
          <span aria-hidden="true"></span>
        </button>
      </div>
      <div class="modal-body" id="modal-body-space">
      </div>
      <div class="modal-footer" id="modal-body-space-buttons">
      </div>
    </div>
  </div>
</div>
<br>
<footer class="footer mt-auto py-3 text-muted ${UI.footer_style_class}" style="${UI.fixed_footer ?'position: fixed; ': ''}left: 0; bottom: 0; width: 100%; color: white; z-index: 9999;${UI.hide_footer ? ' display:none;': ' display:block;'}"> <div class="container" style="width: auto; padding: 0 10px;"> <p class="float-end"> <a href="#">Back to top</a> </p> ${UI.credit ? '<p>Redesigned with <svg width="1em" height="1em" viewBox="0 0 16 16" class="bi bi-heart-fill" fill="red" xmlns="http://www.w3.org/2000/svg"> <path fill-rule="evenodd" d="M8 1.314C12.438-3.248 23.534 4.735 8 15-7.534 4.736 3.562-3.248 8 1.314z" /> </svg> by <a href="https://www.npmjs.com/package/@googledrive/index" target="_blank">TheFirstSpeedster</a>, based on Open Source Softwares.</p>' : ''} <p>© ${UI.copyright_year} - <a href=" ${UI.company_link}" target="_blank"> ${UI.company_name}</a>, All Rights Reserved.</p> </div> </footer>
  `;
    $('body').html(html);
}

const folder_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_11)"><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,24,24)"><path fill="rgb(255,159,0)" fill-opacity="1" d=" M16,-12 C16,-12 -2,-12 -2,-12 C-2,-12 -6,-16 -6,-16 C-6,-16 -16,-16 -16,-16 C-18.200000762939453,-16 -20,-14.199999809265137 -20,-12 C-20,-12 -20,12 -20,12 C-20,14.208999633789062 -18.208999633789062,16 -16,16 C-16,16 13.682000160217285,16 13.682000160217285,16 C13.682000160217285,16 20,5 20,5 C20,5 20,-8 20,-8 C20,-10.199999809265137 18.200000762939453,-12 16,-12z"></path></g></g><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,24,26)"><path fill="rgb(255,201,40)" fill-opacity="1" d=" M16,-14 C16,-14 -16,-14 -16,-14 C-18.200000762939453,-14 -20,-12.199999809265137 -20,-10 C-20,-10 -20,10 -20,10 C-20,12.199999809265137 -18.200000762939453,14 -16,14 C-16,14 16,14 16,14 C18.200000762939453,14 20,12.199999809265137 20,10 C20,10 20,-10 20,-10 C20,-12.199999809265137 18.200000762939453,-14 16,-14z"></path></g></g></g></svg>`;
const video_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_11)"><g transform="matrix(1,0,0,1,24,24)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(63,81,181)" fill-opacity="1" d=" M16,17 C16,17 -16,17 -16,17 C-18.200000762939453,17 -20,15.199999809265137 -20,13 C-20,13 -20,-9 -20,-9 C-20,-9 20,-9 20,-9 C20,-9 20,13 20,13 C20,15.199999809265137 18.200000762939453,17 16,17z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M16,-9 C16,-9 12,-3 12,-3 C12,-3 16,-3 16,-3 C16,-3 20,-9 20,-9 C20,-9 16,-9 16,-9z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M8,-9 C8,-9 4,-3 4,-3 C4,-3 8,-3 8,-3 C8,-3 12,-9 12,-9 C12,-9 8,-9 8,-9z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M0,-9 C0,-9 -4,-3 -4,-3 C-4,-3 0,-3 0,-3 C0,-3 4,-9 4,-9 C4,-9 0,-9 0,-9z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M-8,-9 C-8,-9 -12,-3 -12,-3 C-12,-3 -8,-3 -8,-3 C-8,-3 -4,-9 -4,-9 C-4,-9 -8,-9 -8,-9z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M-16,-9 C-16,-9 -20,-3 -20,-3 C-20,-3 -16,-3 -16,-3 C-16,-3 -12,-9 -12,-9 C-12,-9 -16,-9 -16,-9z"></path></g></g></g><g transform="matrix(1,0,0,1,24,24)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(63,81,181)" fill-opacity="1" d=" M19.399999618530273,-15.699999809265137 C19.399999618530273,-15.699999809265137 -20,-9 -20,-9 C-20,-9 -20.299999237060547,-11 -20.299999237060547,-11 C-20.700000762939453,-13.199999809265137 -19.200000762939453,-15.199999809265137 -17,-15.600000381469727 C-17,-15.600000381469727 14.600000381469727,-20.899999618530273 14.600000381469727,-20.899999618530273 C16.799999237060547,-21.299999237060547 18.799999237060547,-19.799999237060547 19.200000762939453,-17.600000381469727 C19.200000762939453,-17.600000381469727 19.399999618530273,-15.699999809265137 19.399999618530273,-15.699999809265137z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M-5.199999809265137,-17.600000381469727 C-5.199999809265137,-17.600000381469727 -0.30000001192092896,-12.300000190734863 -0.30000001192092896,-12.300000190734863 C-0.30000001192092896,-12.300000190734863 3.700000047683716,-13 3.700000047683716,-13 C3.700000047683716,-13 -1.2999999523162842,-18.299999237060547 -1.2999999523162842,-18.299999237060547 C-1.2999999523162842,-18.299999237060547 -5.199999809265137,-17.600000381469727 -5.199999809265137,-17.600000381469727z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M-13.100000381469727,-16.299999237060547 C-13.100000381469727,-16.299999237060547 -8.199999809265137,-11 -8.199999809265137,-11 C-8.199999809265137,-11 -4.199999809265137,-11.699999809265137 -4.199999809265137,-11.699999809265137 C-4.199999809265137,-11.699999809265137 -9.199999809265137,-16.899999618530273 -9.199999809265137,-16.899999618530273 C-9.199999809265137,-16.899999618530273 -13.100000381469727,-16.299999237060547 -13.100000381469727,-16.299999237060547z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M2.700000047683716,-18.899999618530273 C2.700000047683716,-18.899999618530273 7.599999904632568,-13.699999809265137 7.599999904632568,-13.699999809265137 C7.599999904632568,-13.699999809265137 11.5,-14.300000190734863 11.5,-14.300000190734863 C11.5,-14.300000190734863 6.599999904632568,-19.600000381469727 6.599999904632568,-19.600000381469727 C6.599999904632568,-19.600000381469727 2.700000047683716,-18.899999618530273 2.700000047683716,-18.899999618530273z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M10.5,-20.200000762939453 C10.5,-20.200000762939453 15.5,-15 15.5,-15 C15.5,-15 19.399999618530273,-15.699999809265137 19.399999618530273,-15.699999809265137 C19.399999618530273,-15.699999809265137 14.5,-20.899999618530273 14.5,-20.899999618530273 C14.5,-20.899999618530273 10.5,-20.200000762939453 10.5,-20.200000762939453z"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(159,168,218)" fill-opacity="1" d=" M-16.5,-14 C-17.327999114990234,-14 -18,-13.32800006866455 -18,-12.5 C-18,-11.67199993133545 -17.327999114990234,-11 -16.5,-11 C-15.67199993133545,-11 -15,-11.67199993133545 -15,-12.5 C-15,-13.32800006866455 -15.67199993133545,-14 -16.5,-14z"></path></g></g></g></svg>`;
const code_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_2)"><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,24,21)"><path fill="rgb(83,109,121)" fill-opacity="1" d=" M-18,-13 C-18,-13 18,-13 18,-13 C18,-13 18,13 18,13 C18,13 -18,13 -18,13 C-18,13 -18,-13 -18,-13z"></path></g><g opacity="1" transform="matrix(1,0,0,1,24,20.5)"><path fill="rgb(186,222,250)" fill-opacity="1" d=" M-16,-10.5 C-16,-10.5 16,-10.5 16,-10.5 C16,-10.5 16,10.5 16,10.5 C16,10.5 -16,10.5 -16,10.5 C-16,10.5 -16,-10.5 -16,-10.5z"></path></g><g opacity="1" transform="matrix(1,0,0,1,24,37)"><path fill="rgb(69,90,99)" fill-opacity="1" d=" M-3,-3 C-3,-3 3,-3 3,-3 C3,-3 3,0 3,0 C3,0 -3,0 -3,0 C-3,0 -3,-3 -3,-3z M9,0 C9,0 -9,0 -9,0 C-11,0 -11,2 -11,2 C-11,2 -11,3 -11,3 C-11,3 11,3 11,3 C11,3 11,2 11,2 C11,2 11,0 9,0z"></path></g></g><g transform="matrix(0.8999999761581421,0,0,0.8999999761581421,2.2750015258789062,-1.0999984741210938)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,15.315999984741211,24.465999603271484)"><path fill="rgb(21,101,192)" fill-opacity="1" d=" M-0.8989999890327454,0.02500000037252903 C-0.8989999890327454,0.02500000037252903 3.684000015258789,2.0399999618530273 3.684000015258789,2.0399999618530273 C3.684000015258789,2.0399999618530273 3.684000015258789,4.894999980926514 3.684000015258789,4.894999980926514 C3.684000015258789,4.894999980926514 -3.684000015258789,1.2100000381469727 -3.684000015258789,1.2100000381469727 C-3.684000015258789,1.2100000381469727 -3.684000015258789,-1.1990000009536743 -3.684000015258789,-1.1990000009536743 C-3.684000015258789,-1.1990000009536743 3.684000015258789,-4.894999980926514 3.684000015258789,-4.894999980926514 C3.684000015258789,-4.894999980926514 3.684000015258789,-2.0399999618530273 3.684000015258789,-2.0399999618530273 C3.684000015258789,-2.0399999618530273 -0.8989999890327454,0.02500000037252903 -0.8989999890327454,0.02500000037252903z"></path></g><g opacity="1" transform="matrix(-1,0,0,-1,32.70000076293945,24.465999603271484)"><path fill="rgb(21,101,192)" fill-opacity="1" d=" M-0.8989999890327454,0.02500000037252903 C-0.8989999890327454,0.02500000037252903 3.684000015258789,2.0399999618530273 3.684000015258789,2.0399999618530273 C3.684000015258789,2.0399999618530273 3.684000015258789,4.894999980926514 3.684000015258789,4.894999980926514 C3.684000015258789,4.894999980926514 -3.684000015258789,1.2100000381469727 -3.684000015258789,1.2100000381469727 C-3.684000015258789,1.2100000381469727 -3.684000015258789,-1.1990000009536743 -3.684000015258789,-1.1990000009536743 C-3.684000015258789,-1.1990000009536743 3.684000015258789,-4.894999980926514 3.684000015258789,-4.894999980926514 C3.684000015258789,-4.894999980926514 3.684000015258789,-2.0399999618530273 3.684000015258789,-2.0399999618530273 C3.684000015258789,-2.0399999618530273 -0.8989999890327454,0.02500000037252903 -0.8989999890327454,0.02500000037252903z"></path></g><g opacity="1" transform="matrix(1,0,0,1,24.240999221801758,24)"><path fill="rgb(21,101,192)" fill-opacity="1" d=" M-1.1649999618530273,7.986000061035156 C-1.1649999618530273,7.986000061035156 -3.259000062942505,7.986000061035156 -3.259000062942505,7.986000061035156 C-3.259000062942505,7.986000061035156 1.1619999408721924,-7.916999816894531 1.1619999408721924,-7.916999816894531 C1.1619999408721924,-7.916999816894531 3.259000062942505,-7.916999816894531 3.259000062942505,-7.916999816894531 C3.259000062942505,-7.916999816894531 -1.1649999618530273,7.986000061035156 -1.1649999618530273,7.986000061035156z"></path></g></g></g></svg>`;
const zip_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 32 32"><g transform="translate(0 -1020.362)"><path fill="#e9eded" fill-rule="evenodd" stroke="#4bbfeb" stroke-linecap="round" stroke-linejoin="round" d="m 26.49822,1027.8658 0,21.5 c 0,0.831 -0.66899,1.5 -1.49998,1.5 l -18.00004,0 c -0.83099,0 -1.49998,-0.669 -1.49998,-1.5 l 0,-26 c 0,-0.831 0.66899,-1.5 1.49998,-1.5 l 13.50002,0 z"/><path fill="#4bbfeb" d="m 4.99822,1044.3658 0,2 0,2 0,1 c 0,1.108 0.89198,2 2,2 l 18,0 c 1.10802,0 2,-0.892 2,-2 l 0,-1 0,-2 0,-2 -2,0 -18,0 -2,0 z"/><path fill="#4bbfeb" stroke="#4bbfeb" stroke-linecap="round" stroke-linejoin="round" d="m 26.49466,1027.8658 -4.49997,0 c -0.83099,0 -1.49998,-0.6691 -1.49998,-1.5 l 0,-4.5"/><path style="line-height:normal;text-indent:0;text-align:start;text-decoration-line:none;text-decoration-style:solid;text-decoration-color:#000;text-transform:none;block-progression:tb;isolation:auto;mix-blend-mode:normal" fill="#4bbfeb" fill-rule="evenodd" d="M 15.498047 7 L 15.498047 8 L 14.498047 8 L 14.498047 9 L 15.498047 9 L 15.498047 10 L 14.498047 10 L 14.498047 11 L 15.498047 11 L 15.498047 12 L 14.498047 12 L 14.498047 13 L 15.498047 13 L 15.498047 14 L 14.498047 14 L 14.498047 15 L 15.498047 15 L 15.498047 16 L 14.498047 16 L 14.498047 17 L 15.498047 17 L 15.498047 18 L 14.998047 18 A 0.50004997 0.50004997 0 0 0 14.498047 18.5 L 14.498047 19.464844 A 0.50004997 0.50004997 0 0 0 14.498047 19.5 L 14.498047 20 L 14.498047 20.5 C 14.498047 21.3224 15.175696 22 15.998047 22 C 16.820398 22 17.498047 21.3224 17.498047 20.5 L 17.498047 20.033203 A 0.50004997 0.50004997 0 0 0 17.498047 20 L 17.498047 19.5 L 17.498047 18.5 A 0.50004997 0.50004997 0 0 0 16.998047 18 L 16.498047 18 L 16.498047 17 L 17.498047 17 L 17.498047 16 L 16.498047 16 L 16.498047 15 L 17.498047 15 L 17.498047 14 L 16.498047 14 L 16.498047 13 L 17.498047 13 L 17.498047 12 L 16.498047 12 L 16.498047 11 L 17.498047 11 L 17.498047 10 L 16.498047 10 L 16.498047 9 L 17.498047 9 L 17.498047 8 L 16.498047 8 L 16.498047 7 L 15.498047 7 z M 15.498047 19 L 16.498047 19 L 16.498047 19.5 L 16.498047 20.5 C 16.498047 20.7857 16.283696 21 15.998047 21 C 15.712398 21 15.498047 20.7857 15.498047 20.5 L 15.498047 20.033203 A 0.50004997 0.50004997 0 0 0 15.498047 20 L 15.498047 19.5 L 15.498047 19 z " color="#000" font-family="sans-serif" font-weight="400" overflow="visible" transform="translate(0 1020.362)"/><path style="line-height:normal;text-indent:0;text-align:start;text-decoration-line:none;text-decoration-style:solid;text-decoration-color:#000;text-transform:none;block-progression:tb;isolation:auto;mix-blend-mode:normal" fill="#e9eded" fill-rule="evenodd" d="M 13.490234 24.990234 A 0.50005 0.50005 0 0 0 12.998047 25.496094 L 12.998047 29.498047 A 0.50005 0.50005 0 1 0 13.998047 29.498047 L 13.998047 25.496094 A 0.50005 0.50005 0 0 0 13.490234 24.990234 z M 11.511719 24.998047 A 0.50005 0.50005 0 0 0 11.460938 25 L 8.5058594 25 A 0.50005 0.50005 0 1 0 8.5058594 26 L 10.498047 26 L 8.1347656 29.154297 A 0.50005 0.50005 0 0 0 8.4375 29.992188 A 0.50019268 0.50019268 0 0 0 8.4472656 29.994141 A 0.50005 0.50005 0 0 0 8.5058594 29.998047 L 11.494141 29.998047 A 0.50005 0.50005 0 1 0 11.494141 28.998047 L 9.5019531 28.998047 L 11.865234 25.841797 A 0.50005 0.50005 0 0 0 11.75 25.066406 A 0.50005 0.50005 0 0 0 11.720703 25.050781 A 0.50005 0.50005 0 0 0 11.705078 25.042969 A 0.50005 0.50005 0 0 0 11.675781 25.03125 A 0.50005 0.50005 0 0 0 11.658203 25.025391 A 0.50005 0.50005 0 0 0 11.511719 24.998047 z M 16.498047 25.003906 C 15.723646 25.003906 15.086569 25.606569 15.013672 26.363281 C 15.013355 26.366575 15.012014 26.369747 15.011719 26.373047 A 0.50005 0.50005 0 0 0 14.998047 26.498047 C 14.998039 26.500027 14.998047 26.501925 14.998047 26.503906 L 14.998047 29.498047 A 0.50005 0.50005 0 1 0 15.998047 29.498047 L 15.998047 27.910156 C 16.155295 27.966775 16.322382 28.003906 16.498047 28.003906 C 17.320552 28.003906 17.998047 27.326406 17.998047 26.503906 C 17.998047 25.681406 17.320552 25.003906 16.498047 25.003906 z M 16.498047 26.003906 C 16.780112 26.003906 16.998047 26.221906 16.998047 26.503906 C 16.998047 26.786006 16.780112 27.003906 16.498047 27.003906 C 16.215982 27.003906 15.998047 26.786006 15.998047 26.503906 L 15.998047 26.498047 C 16.001131 26.218978 16.217997 26.003906 16.498047 26.003906 z " color="#000" font-family="sans-serif" font-weight="400" overflow="visible" transform="translate(0 1020.362)"/></g></svg>`;
const image_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_19)"><g transform="matrix(1,0,0,1,24,24)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(245,124,0)" fill-opacity="1" d=" M16,17 C16,17 -16,17 -16,17 C-18.200000762939453,17 -20,15.199999809265137 -20,13 C-20,13 -20,-13 -20,-13 C-20,-15.199999809265137 -18.200000762939453,-17 -16,-17 C-16,-17 16,-17 16,-17 C18.200000762939453,-17 20,-15.199999809265137 20,-13 C20,-13 20,13 20,13 C20,15.199999809265137 18.200000762939453,17 16,17z"></path></g></g><g transform="matrix(1,0,0,1,35,16)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(255,249,196)" fill-opacity="1" d=" M0,-3 C-1.656999945640564,-3 -3,-1.656999945640564 -3,0 C-3,1.656999945640564 -1.656999945640564,3 0,3 C1.656999945640564,3 3,1.656999945640564 3,0 C3,-1.656999945640564 1.656999945640564,-3 0,-3z"></path></g></g><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,20,24)"><path fill="rgb(148,42,9)" fill-opacity="1" d=" M0,-8 C0,-8 -11,8 -11,8 C-11,8 11,8 11,8 C11,8 0,-8 0,-8z"></path></g><g opacity="1" transform="matrix(1,0,0,1,31,27)"><path fill="rgb(191,54,12)" fill-opacity="1" d=" M0,-5 C0,-5 -8,5 -8,5 C-8,5 8,5 8,5 C8,5 0,-5 0,-5z"></path></g></g></g></svg>`;
const audio_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_30)"><g mask="url(#__lottie_element_41)" transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,26,24)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(129,211,249)" stroke-opacity="1" stroke-width="2" d=" M-16,0 C-16,-8.836000442504883 -8.836000442504883,-16 0,-16 C0.6779999732971191,-16 1.3450000286102295,-15.958000183105469 2,-15.87600040435791 C9.892999649047852,-14.892000198364258 16,-8.159000396728516 16,0 C16,8.159000396728516 9.892999649047852,14.892000198364258 2,15.87600040435791 C1.3450000286102295,15.958000183105469 0.6779999732971191,16 0,16 C-8.836000442504883,16 -16,8.836999893188477 -16,0z"></path></g></g><g mask="url(#__lottie_element_38)" style="display: none;" transform="matrix(1,0,0,1,0,0)" opacity="1"><g opacity="1" transform="matrix(1,0,0,1,26,24)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(129,211,249)" stroke-opacity="1" stroke-width="2" d=" M-16,0 C-16,-8.836000442504883 -8.836000442504883,-16 0,-16 C0.6779999732971191,-16 1.3450000286102295,-15.958000183105469 2,-15.87600040435791 C9.892999649047852,-14.892000198364258 16,-8.159000396728516 16,0 C16,8.159000396728516 9.892999649047852,14.892000198364258 2,15.87600040435791 C1.3450000286102295,15.958000183105469 0.6779999732971191,16 0,16 C-8.836000442504883,16 -16,8.836999893188477 -16,0z"></path></g></g><g mask="url(#__lottie_element_35)" transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,26,24)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(79,195,247)" stroke-opacity="1" stroke-width="2" d=" M-11,0 C-11,-6.074999809265137 -6.074999809265137,-11 0,-11 C0.6830000281333923,-11 1.3519999980926514,-10.937999725341797 2,-10.819000244140625 C7.119999885559082,-9.878000259399414 11,-5.392000198364258 11,0 C11,5.39300012588501 7.119999885559082,9.878000259399414 2,10.817999839782715 C1.3519999980926514,10.937999725341797 0.6830000281333923,11 0,11 C-6.074999809265137,11 -11,6.074999809265137 -11,0z"></path></g><g opacity="1" transform="matrix(1,0,0,1,26,24)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(3,169,244)" stroke-opacity="1" stroke-width="2" d=" M-6,0 C-6,-3.312999963760376 -3.312999963760376,-6 0,-6 C0.7009999752044678,-6 1.375,-5.880000114440918 2,-5.658999919891357 C4.329999923706055,-4.835000038146973 6,-2.611999988555908 6,0 C6,2.611999988555908 4.329999923706055,4.835000038146973 2,5.6579999923706055 C1.375,5.880000114440918 0.7009999752044678,6 0,6 C-3.312999963760376,6 -6,3.312999963760376 -6,0z"></path></g></g><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,9.5,24)"><path fill="rgb(83,109,121)" fill-opacity="1" d=" M4.5,8 C4.5,8 -2.5,8 -2.5,8 C-3.6050000190734863,8 -4.5,7.105000019073486 -4.5,6 C-4.5,6 -4.5,-6 -4.5,-6 C-4.5,-7.105000019073486 -3.6050000190734863,-8 -2.5,-8 C-2.5,-8 4.5,-8 4.5,-8 C4.5,-8 4.5,8 4.5,8z"></path></g><g opacity="1" transform="matrix(1,0,0,1,20,24)"><path fill="rgb(120,144,156)" fill-opacity="1" d=" M6,18 C6,18 -6,8 -6,8 C-6,8 -6,-8 -6,-8 C-6,-8 6,-18 6,-18 C6,-18 6,18 6,18z"></path></g></g></g></svg>`;
const markdown_icon = `<svg width="1.5em" height="1.5em" viewBox="0 0 1024 1024"><path d="M265.61429932 63.6656706h493.57455644c111.51629209 0 201.91670068 90.40220771 201.91670068 201.91580157v493.57545556c0 111.51449297-90.40040859 201.91670068-201.91670068 201.91670069H265.61429932c-111.51539297 0-201.91580068-90.40220771-201.91580069-201.91670069V265.58147217c0-111.51359385 90.40040859-201.91580068 201.91580069-201.91580157z" fill="#707070"></path><path d="M763.60576133 722.16141084L670.49099316 599.42972305h48.19382491V302.57788818h89.84188652v296.85183487h48.19382491L763.60576133 722.16141084zM519.02738545 472.82885791c0-13.71570117 0.30399346-28.21926709 0.91827773-43.48821445l-13.67612753 19.09855107c-0.1726831 0.54323174-0.34626533 1.10265205-0.52074757 1.62609698l-7.15195107 10.50577734-109.52234384 166.63092451-40.52562364-62.91054668h-0.25092949l-28.34248359-44.38850449-41.19926749-63.95563828h0.36425304l-8.60086846-13.47016729-0.46318536-1.8752291-14.42082305-21.30475518c1.05318633 33.22347451 1.60451191 57.42426622 1.60451192 72.50254365v229.53787296h-89.15835059V303.99532753h140.37862325l77.89348828 115.26944679h1.3346956l80.12037832-115.26944678H610.08255019v417.34224141H519.02828457V472.82885791z" fill="#ffffff"></path></svg>`;
const pdf_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_44)"><g transform="matrix(1,0,0,1,0,0)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,24,24)"><path fill="rgb(255,87,34)" fill-opacity="1" d=" M16,21 C16,21 -16,21 -16,21 C-16,21 -16,-21 -16,-21 C-16,-21 6,-21 6,-21 C6,-21 16,-11 16,-11 C16,-11 16,21 16,21z"></path></g><g opacity="1" transform="matrix(1,0,0,1,33.75,9.25)"><path fill="rgb(251,233,231)" fill-opacity="1" d=" M4.75,4.75 C4.75,4.75 -4.75,4.75 -4.75,4.75 C-4.75,4.75 -4.75,-4.75 -4.75,-4.75 C-4.75,-4.75 4.75,4.75 4.75,4.75z"></path></g></g><g transform="matrix(1,0,0,1,24,24)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path fill="rgb(255,255,255)" fill-opacity="1" d=" M-8,15 C-8.399999618530273,15 -8.699999809265137,14.899999618530273 -9,14.800000190734863 C-10.100000381469727,14.199999809265137 -10.199999809265137,13.300000190734863 -10,12.600000381469727 C-9.600000381469727,11.399999618530273 -7.400000095367432,9.899999618530273 -4.5,8.600000381469727 C-4.5,8.600000381469727 -4.5,8.600000381469727 -4.5,8.600000381469727 C-3.200000047683716,6.199999809265137 -2.200000047683716,3.700000047683716 -1.600000023841858,1.600000023841858 C-2.5999999046325684,-0.30000001192092896 -3.0999999046325684,-2.0999999046325684 -3.0999999046325684,-3.4000000953674316 C-3.0999999046325684,-4.099999904632568 -2.9000000953674316,-4.699999809265137 -2.5999999046325684,-5.199999809265137 C-2.200000047683716,-5.699999809265137 -1.600000023841858,-6 -0.800000011920929,-6 C0.10000000149011612,-6 0.800000011920929,-5.5 1.100000023841858,-4.599999904632568 C1.600000023841858,-3.4000000953674316 1.2999999523162842,-1.2000000476837158 0.6000000238418579,1.2999999523162842 C1.600000023841858,3 2.799999952316284,4.599999904632568 4.099999904632568,5.800000190734863 C6,5.400000095367432 7.699999809265137,5.199999809265137 8.800000190734863,5.400000095367432 C10.699999809265137,5.699999809265137 11,7 11,7.5 C11,9.600000381469727 8.800000190734863,9.600000381469727 8,9.600000381469727 C6.5,9.600000381469727 5,9 3.700000047683716,7.900000095367432 C3.700000047683716,7.900000095367432 3.700000047683716,7.900000095367432 3.700000047683716,7.900000095367432 C1.2999999523162842,8.5 -1.100000023841858,9.300000190734863 -3,10.199999809265137 C-4,11.899999618530273 -5,13.300000190734863 -5.900000095367432,14.100000381469727 C-6.800000190734863,14.800000190734863 -7.5,15 -8,15z M-6.800000190734863,12.100000381469727 C-7.300000190734863,12.399999618530273 -7.699999809265137,12.699999809265137 -7.900000095367432,13 C-7.699999809265137,12.899999618530273 -7.300000190734863,12.699999809265137 -6.800000190734863,12.100000381469727z M6.800000190734863,7.400000095367432 C7.199999809265137,7.5 7.599999904632568,7.599999904632568 8,7.599999904632568 C8.600000381469727,7.599999904632568 8.899999618530273,7.5 9,7.5 C9,7.5 9,7.5 9,7.5 C8.899999618530273,7.400000095367432 8.199999809265137,7.199999809265137 6.800000190734863,7.400000095367432z M-0.20000000298023224,3.799999952316284 C-0.6000000238418579,5 -1.2000000476837158,6.300000190734863 -1.7000000476837158,7.5 C-0.5,7.099999904632568 0.699999988079071,6.699999809265137 1.899999976158142,6.400000095367432 C1.100000023841858,5.599999904632568 0.4000000059604645,4.699999809265137 -0.20000000298023224,3.799999952316284z M-0.800000011920929,-4 C-0.8999999761581421,-4 -0.8999999761581421,-4 -0.8999999761581421,-4 C-1,-3.9000000953674316 -1.100000023841858,-3.200000047683716 -0.699999988079071,-1.7000000476837158 C-0.6000000238418579,-2.9000000953674316 -0.6000000238418579,-3.799999952316284 -0.800000011920929,-4z"></path></g></g></g></svg>`;
const file_icon = `<svg xmlns="http://www.w3.org/2000/svg" width="1.5em" height="1.5em" viewBox="0 0 48 48" preserveAspectRatio="xMidYMid meet"><g clip-path="url(#__lottie_element_63)"><g transform="matrix(1,0,0,1,7.75,2.75)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,16.25,21.25)"><path fill="rgb(144,201,248)" fill-opacity="1" d=" M16,21 C16,21 -16,21 -16,21 C-16,21 -16,-21 -16,-21 C-16,-21 6,-21 6,-21 C6,-21 16,-11 16,-11 C16,-11 16,21 16,21z"></path></g></g><g transform="matrix(1,0,0,1,15,21)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(24,118,210)" stroke-opacity="1" stroke-width="2" d=" M1,1 C1,1 18,1 18,1"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(24,118,210)" stroke-opacity="1" stroke-width="2" d=" M1,5 C1,5 14,5 14,5"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(24,118,210)" stroke-opacity="1" stroke-width="2" d=" M1,9 C1,9 18,9 18,9"></path></g><g opacity="1" transform="matrix(1,0,0,1,0,0)"><path stroke-linecap="butt" stroke-linejoin="miter" fill-opacity="0" stroke-miterlimit="10" stroke="rgb(24,118,210)" stroke-opacity="1" stroke-width="2" d=" M1,13 C1,13 14,13 14,13"></path></g></g><g transform="matrix(1,0,0,1,28.75,4.25)" opacity="1" style="display: block;"><g opacity="1" transform="matrix(1,0,0,1,5,5)"><path fill="rgb(224,245,253)" fill-opacity="1" d=" M4.75,4.75 C4.75,4.75 -4.75,4.75 -4.75,4.75 C-4.75,4.75 -4.75,-4.75 -4.75,-4.75 C-4.75,-4.75 0,0 0,0 C0,0 4.75,4.75 4.75,4.75z"></path></g></g></g></svg>`;

// Don't know new OS thing, so I just copied it from the original source code and edited something.
const Os = {
    isWindows: navigator.userAgent.toUpperCase().indexOf('WIN') > -1, // .includes
    isMac: navigator.userAgent.toUpperCase().indexOf('MAC') > -1,
    isMacLike: /(Mac|iPhone|iPod|iPad)/i.test(navigator.userAgent),
    isIos: /(iPhone|iPod|iPad)/i.test(navigator.userAgent),
    isMobile: /Android|webOS|iPhone|iPad|iPod|iOS|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)
};

function getDocumentHeight() {
    const D = document;
    return Math.max(
        D.body.scrollHeight, D.documentElement.scrollHeight,
        D.body.offsetHeight, D.documentElement.offsetHeight,
        D.body.clientHeight, D.documentElement.clientHeight
    );
}

// get search params
function getQueryVariable(variable) {
    const query = window.location.search.substring(1);
    const vars = query.split('&');
    let pair;
    for (let i = 0; i < vars.length; i++) {
        pair = vars[i].split('=');
        if (pair[0] == variable) {
            return pair[1];
        }
    }
    return (false);
}

function render(path) {
    if (path.indexOf("?") > 0) {
        path = path.substr(0, path.indexOf("?"));
    }
    title(path);
    nav(path);
    // .../0: This
    const reg = /\/\d+:$/g;
    if (path.includes("/fallback")) {
        // Used to store the state of some scroll events
        window.scroll_status = {
            // Whether the scroll event is bound
            event_bound: false,
            // "Scroll to the bottom, loading more data" event lock
            loading_lock: false
        };
        const can_preview = getQueryVariable('a');
        const id = getQueryVariable('id');
        if (can_preview) {
            return fallback(id, true);
        } else {
            return list(null, id, true);
        }
    } else if (window.MODEL.is_search_page) {
        // Used to store the state of some scroll events
        window.scroll_status = {
            // Whether the scroll event is bound
            event_bound: false,
            // "Scroll to the bottom, loading more data" event lock
            loading_lock: false
        };
        render_search_result_list();
    } else if (path.match(reg) || path.slice(-1) == '/') {
        // Used to store the state of some scroll events
        window.scroll_status = {
            // Whether the scroll event is bound
            event_bound: false,
            // "Scroll to the bottom, loading more data" event lock
            loading_lock: false
        };
        list(path);
    } else {
        file(path);
    }
}


// Render title
function title(path) {
    path = decodeURI(path);
    const cur = window.current_drive_order || 0;
    const drive_name = window.drive_names[cur];
    path = path.replace(`/${cur}:`, '');
    // $('title').html(document.siteName + ' - ' + path);
    const model = window.MODEL;
    if (model.is_search_page)
        $('title').html(`${drive_name} - Search results for ${model.q} `);
    else
        $('title').html(`${drive_name} - ${path}`);
}

// Render the navigation bar
function nav(path) {
    const model = window.MODEL;
    let html = "";
    const cur = window.current_drive_order || 0;
    html += `<nav class="navbar navbar-expand-lg${UI.fixed_header ?' fixed-top': ''} ${UI.header_style_class}">
    <div class="container-fluid">
  <a class="navbar-brand" href="/">${UI.logo_image ? '<img border="0" alt="'+UI.company_name+'" src="'+UI.logo_link_name+'" height="'+UI.logo_height+'" width="'+UI.logo_width+'">' : UI.logo_link_name}</a>
  <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbarSupportedContent">
    <ul class="navbar-nav me-auto mb-2 mb-lg-0">
      <li class="nav-item">
        <a class="nav-link" href="/${cur}:/">${UI.nav_link_1}</a>
      </li>`;
    const names = window.drive_names;
    const drive_name = window.drive_names[cur];

    // Dropdown to select different drive roots.
    html += `<li class="nav-item dropdown"><a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">${drive_name}</a><div class="dropdown-menu" aria-labelledby="navbarDropdown">`;
    names.forEach((name, idx) => {
        html += `<a class="dropdown-item"  href="/${idx}:/">${name}</a>`;
    });
    html += `</div></li>`;


    html += `<li class="nav-item">
    <a class="nav-link" href="${UI.contact_link}" target="_blank">${UI.nav_link_4}</a>
  </li>${UI.show_logout_button ?'<li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li>': ''}`;

    const search_text = model.is_search_page ? (model.q || '') : '';
    const search_bar = `
</ul>
<form class="d-flex" method="get" action="/${cur}:search">
<input class="form-control me-2" name="q" type="search" placeholder="Search" aria-label="Search" value="${search_text}" required>
<button class="btn ${UI.search_button_class}" onclick="if($('#search_bar_form>input').val()) $('#search_bar_form').submit();" type="submit">Search</button>
</form>
</div>
</div>
</nav>
`;

    // Personal or team
    if (model.root_type < 2) {
        // Show search box
        html += search_bar;
    }

    $('#nav').html(html);
}

// Sleep Function to Retry API Calls
function sleep(milliseconds) {
    const date = Date.now();
    let currentDate = null;
    do {
        currentDate = Date.now();
    } while (currentDate - date < milliseconds);
}

/**
 * Initiate POST request for listing
 * @param path Path
 * @param params Form params
 * @param resultCallback Success Result Callback
 * @param authErrorCallback Pass Error Callback
 */
function requestListPath(path, params, resultCallback, authErrorCallback, retries = 3, fallback = false) {
    const requestData = {
        id: params['id'] || '',
        type: 'folder',
        password: params['password'] || '',
        page_token: params['page_token'] || '',
        page_index: params['page_index'] || 0
    };
    $('#update').show();
    document.getElementById('update').innerHTML = `<div class='alert alert-info' role='alert'> Connecting...</div></div></div>`;
    if (fallback) {
        path = "/0:fallback";
    }

    function performRequest() {
        fetch(fallback ? "/0:fallback" : path, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('Request failed');
                }
                return response.json();
            })
            .then(function(res) {
                if (res && res.error && res.error.code === 401) {
                    // Password verification failed
                    askPassword(path);
                } else if (res && res.data === null) {
                    document.getElementById('spinner').remove();
                    document.getElementById('list').innerHTML = `<div class='alert alert-danger' role='alert'> Server didn't send any data.</div></div></div>`;
                    $('#update').hide();
                } else if (res && res.data) {
                    resultCallback(res, path, requestData);
                    $('#update').hide();
                }
            })
            .catch(function(error) {
                if (retries > 0) {
                    sleep(2000);
                    document.getElementById('update').innerHTML = `<div class='alert alert-info' role='alert'> Retrying...</div></div></div>`;
                    performRequest(path, requestData, resultCallback, authErrorCallback, retries - 1);
                } else {
                    document.getElementById('update').innerHTML = `<div class='alert alert-danger' role='alert'> Unable to get data from the server. Something went wrong.</div></div></div>`;
                    document.getElementById('list').innerHTML = `<div class='alert alert-danger' role='alert'> We were unable to get data from the server. ` + error + `</div></div></div>`;
                    $('#update').hide();
                }
            });
    }
    console.log("Performing Request again");
    performRequest();
}




/**
 * Search POST request
 * @param params Form params
 * @param resultCallback Success callback
 */
function requestSearch(params, resultCallback, retries = 3) {
    const p = {
        q: params['q'] || null,
        page_token: params['page_token'] || null,
        page_index: params['page_index'] || 0
    };

    function performRequest(retries) {
        fetch(`/${window.current_drive_order}:search`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(p)
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('Request failed');
                }
                return response.json();
            })
            .then(function(res) {
                if (res && res.data === null) {
                    $('#spinner').remove();
                    $('#list').html(`<div class='alert alert-danger' role='alert'> Server didn't send any data.</div></div></div>`);
                    $('#update').remove();
                }
                if (res && res.data) {
                    if (resultCallback) resultCallback(res, p);
                    $('#update').remove();
                }
            })
            .catch(function(error) {
                if (retries > 0) {
                    sleep(2000);
                    $('#update').html(`<div class='alert alert-info' role='alert'> Retrying...</div></div></div>`);
                    performRequest(retries - 1);
                } else {
                    $('#update').html(`<div class='alert alert-danger' role='alert'> Unable to get data from the server. Something went wrong. 3 Failures</div></div></div>`);
                    $('#list').html(`<div class='alert alert-danger' role='alert'> We were unable to get data from the server.</div></div></div>`);
                    $('#spinner').remove();
                }
            });
    }

    $('#update').html(`<div class='alert alert-info' role='alert'> Connecting...</div></div></div>`);
    performRequest(retries);
}


// Render file list
function list(path, id = '', fallback = false) {
    console.log(id);
    let containerContent = `<div class="container">${UI.fixed_header ?'<br>': ''}
    <div id="update"></div>
    <div id="head_md" style="display:none; padding: 20px 20px;"></div>
    <div class="container" id="select_items" style="padding: 0px 50px 10px; display:none;">
      <div class="d-flex align-items-center justify-content-between">
        <div class="form-check mr-3">
          <input class="form-check-input" style="margin-top: 0.3em;margin-right: 0.5em;" type="checkbox" id="select-all-checkboxes">
          <label class="form-check-label" for="select-all-checkboxes">Select all</label>
        </div>
        <button id="handle-multiple-items-copy" style="padding: 5px 10px; font-size: 12px;" class="btn btn-success">Copy</button>
      </div>
    </div>
    <div class="${UI.path_nav_alert_class} d-flex align-items-center" role="alert" style="margin-bottom: 0; padding-bottom: 0rem;">
      <nav style="--bs-breadcrumb-divider: '>';" aria-label="breadcrumb">
        <ol class="breadcrumb" id="folderne">
          <li class="breadcrumb-item"><a href="/">Home</a></li>`;

    const navfulllink = window.location.pathname;
    const navarray = navfulllink.trim('/').split('/');
    let currentPath = '/';

    if (navarray.length > 1) {
        for (const i in navarray) {
            const pathPart = navarray[i];
            const decodedPathPart = decodeURIComponent(pathPart).replace(/\//g, '%2F');
            const trimmedPathPart = decodedPathPart.replace(/\?.+/g, "$'");

            const displayedPathPart = trimmedPathPart.length > 15 ? trimmedPathPart.slice(0, 5) + '...' : trimmedPathPart.slice(0, 15);

            currentPath += pathPart + '/';

            if (displayedPathPart === '') {
                break;
            }

            containerContent += `<li class="breadcrumb-item"><a href="${currentPath}">${displayedPathPart}</a></li>`;
        }
    }

    containerContent += `</ol>
    </nav>
  </div>
  <div id="list" class="list-group text-break"></div>
  <div class="${UI.file_count_alert_class} text-center d-none" role="alert" id="count"><span class="number text-center"></span> | <span class="totalsize text-center"></span></div>
  <div id="readme_md" style="display:none; padding: 20px 20px;"></div>
</div>`;

    $('#content').html(containerContent);

    const password = localStorage.getItem('password' + path);

    $('#list').html(`<div class="d-flex justify-content-center"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`);
    $('#readme_md').hide().html('');
    $('#head_md').hide().html('');

    function handleSuccessResult(res, path, prevReqParams) {
        console.log(res, path, prevReqParams);
        $('#list')
            .data('nextPageToken', res['nextPageToken'])
            .data('curPageIndex', res['curPageIndex']);

        $('#spinner').remove();

        if (res['nextPageToken'] === null) {
            $(window).off('scroll');
            window.scroll_status.event_bound = false;
            window.scroll_status.loading_lock = false;
            if (fallback) {
                append_files_to_fallback_list(path, res['data']['files']);
            } else {
                append_files_to_list(path, res['data']['files']);
            }
        } else {
            console.log('doing something...');
            if (fallback) {
                append_files_to_fallback_list(path, res['data']['files']);
            } else {
                append_files_to_list(path, res['data']['files']);
            }
            if (window.scroll_status.event_bound !== true) {
                $(window).on('scroll', function() {
                    const scrollTop = $(this).scrollTop();
                    const scrollHeight = getDocumentHeight();
                    const windowHeight = $(this).height();

                    if (scrollTop + windowHeight > scrollHeight - (Os.isMobile ? 130 : 80)) {
                        if (window.scroll_status.loading_lock === true) {
                            return;
                        }

                        window.scroll_status.loading_lock = true;

                        $(`<div id="spinner" class="d-flex justify-content-center"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`)
                            .insertBefore('#readme_md');

                        const $list = $('#list');
                        if (fallback) {
                            console.log('fallback inside handleSuccessResult');
                            requestListPath(path, {
                                    id: id,
                                    password: prevReqParams['password'],
                                    page_token: $list.data('nextPageToken'),
                                    page_index: $list.data('curPageIndex') + 1
                                },
                                handleSuccessResult,
                                null, 5, id, fallback = true);
                        } else {
                            requestListPath(path, {
                                    password: prevReqParams['password'],
                                    page_token: $list.data('nextPageToken'),
                                    page_index: $list.data('curPageIndex') + 1
                                },
                                handleSuccessResult,
                                null);
                        }
                    }
                });

                window.scroll_status.event_bound = true;
            }
        }

        if (window.scroll_status.loading_lock === true) {
            window.scroll_status.loading_lock = false;
        }
    }

    if (fallback) {
        console.log('fallback inside list');
        requestListPath(path, {
                id: id,
                password: password
            },
            handleSuccessResult,
            null, null, fallback = true);
    } else {
        console.log("handling this");
        requestListPath(path, {
                password: password
            },
            handleSuccessResult,
            null);
    }


    const copyBtn = document.getElementById("handle-multiple-items-copy");

    // Add a click event listener to the copy button
    copyBtn.addEventListener("click", () => {
        // Get all the checked checkboxes
        const checkedItems = document.querySelectorAll('input[type="checkbox"]:checked');

        // Create an array to store the selected items' data
        const selectedItemsData = [];

        // Loop through each checked checkbox
        if (checkedItems.length === 0) {
            alert("No items selected!");
            return;
        }
        checkedItems.forEach((item) => {
            // Get the value of the checkbox (in this case, the URL)
            const itemData = item.value;
            // Push the value to the array
            selectedItemsData.push(itemData);
        });

        // Join the selected items' data with a newline character
        const dataToCopy = selectedItemsData.join("\n");

        // Create a temporary input element
        const tempInput = document.createElement("textarea");
        tempInput.value = dataToCopy;

        // Add the temporary input element to the document
        document.body.appendChild(tempInput);

        // Select the text inside the temporary input element
        tempInput.select();

        // Copy the selected text to the clipboard
        document.execCommand("copy");

        // Remove the temporary input element from the document
        document.body.removeChild(tempInput);

        // Alert the user that the data has been copied
        alert("Selected items copied to clipboard!");
    });
}

function askPassword(path) {
    $('#spinner').remove();
    const passwordInput = prompt("Directory encryption, please enter the password", "");
    localStorage.setItem('password' + path, passwordInput);

    if (passwordInput != null && passwordInput != "") {
        list(path);
    } else {
        history.go(-1);
    }
}

/**
 * Append the data of the requested new page to the list
 * @param path
 * @param files request result
 */
function append_files_to_fallback_list(path, files) {
    try {
        console.log('append_files_to_fallback_list');
        const $list = $('#list');
        // Is it the last page of data?
        const is_lastpage_loaded = null === $list.data('nextPageToken');
        const is_firstpage = '0' == $list.data('curPageIndex');

        let html = "";
        const targetFiles = [];
        let totalsize = 0;
        let is_file = false;
        for (const i in files) {
            const item = files[i];
            const p = "/fallback?id=" + item.id;
            item['modifiedTime'] = utc2delhi(item['modifiedTime']);
            // replace / with %2F
            if (item['mimeType'] == 'application/vnd.google-apps.folder') {
                html += `<a href="${p}" style="color: ${UI.folder_text_color};" class="countitems list-group-item list-group-item-action"> ${folder_icon} ${item.name} ${UI.display_time ? `<span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</a>`;
            } else {
                totalsize = totalsize + Number(item.size);
                item['size'] = formatFileSize(item['size']);
                is_file = true;
                const epn = item.name;
                const link = UI.second_domain_for_dl ? UI.downloaddomain + item.link : window.location.origin + item.link;
                let pn = path + epn.replace(new RegExp('#', 'g'), '%23').replace(new RegExp('\\?', 'g'), '%3F');
                let c = "file";
                // README is displayed after the last page is loaded, otherwise it will affect the scroll event
                if (is_lastpage_loaded && item.name == "README.md" && UI.render_readme_md) {
                    get_file(p, item, function(data) {
                        markdown("#readme_md", data);
                        $("img").addClass("img-fluid");
                    });
                }
                if (item.name == "HEAD.md" && UI.render_head_md) {
                    get_file(p, item, function(data) {
                        markdown("#head_md", data);
                        $("img").addClass("img-fluid");
                    });
                }
                const ext = item.fileExtension;
                //if ("|html|php|css|go|java|js|json|txt|sh|md|mp4|webm|avi|bmp|jpg|jpeg|png|gif|m4a|mp3|flac|wav|ogg|mpg|mpeg|mkv|rm|rmvb|mov|wmv|asf|ts|flv|pdf|".indexOf(`|${ext}|`) >= 0) {
                //targetFiles.push(filepath);
                pn += "?a=view";
                c += " view";
                //}
                html += `<div class="list-group-item list-group-item-action">${UI.allow_selecting_files ? '<input class="form-check-input" style="margin-top: 0.3em;margin-right: 0.5em;" type="checkbox" value="'+link+'" id="flexCheckDefault">' : ''}`;

                // Use centralized getFileIcon helper
                html += getFileIcon(ext);

                html += ` <a class="countitems size_items list-group-item-action" style="text-decoration: none; color: ${UI.css_a_tag_color};" href="${p}&a=view">${item.name}</a>${UI.display_download ? `<a href="${link}"><svg class="float-end"width="25px" style="margin-left: 8px;" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"> <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"></path> <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"></path> </svg></a>` : ``}${UI.display_size ? `<span class="badge bg-primary float-end"> ` + item['size'] + ` </span>` : ``}${UI.display_time ? ` <span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</div>`;
            }
        }
        if (is_file && UI.allow_selecting_files) {
            document.getElementById('select_items').style.display = 'block';
        }


        /*let targetObj = {};
        targetFiles.forEach((myFilepath, myIndex) => {
            if (!targetObj[myFilepath]) {
                targetObj[myFilepath] = {
                    filepath: myFilepath,
                    prev: myIndex === 0 ? null : targetFiles[myIndex - 1],
                    next: myIndex === targetFiles.length - 1 ? null : targetFiles[myIndex + 1],
                }
            }
        })
        // console.log(targetObj)
        if (Object.keys(targetObj).length) {
            localStorage.setItem(path, JSON.stringify(targetObj));
            // console.log(path)
        }*/

        if (targetFiles.length > 0) {
            const old = localStorage.getItem(path);
            let new_children = targetFiles;
            // Reset on page 1; otherwise append
            if (!is_firstpage && old) {
                let old_children;
                try {
                    old_children = JSON.parse(old);
                    if (!Array.isArray(old_children)) {
                        old_children = [];
                    }
                } catch (e) {
                    old_children = [];
                }
                new_children = old_children.concat(targetFiles);
            }

            localStorage.setItem(path, JSON.stringify(new_children));
        }

        // When it is page 1, remove the horizontal loading bar
        $list.html(($list.data('curPageIndex') == '0' ? '' : $list.html()) + html);
        // When it is the last page, count and display the total number of items
        if (is_lastpage_loaded) {
            const total_size = formatFileSize(totalsize) || '0 Bytes';
            const total_items = $list.find('.countitems').length;
            const total_files = $list.find('.size_items').length;
            if (total_items == 0) {
                $('#count').removeClass('d-none').find('.number').text("Empty Folder");
            } else if (total_items == 1) {
                $('#count').removeClass('d-none').find('.number').text(total_items + " item");
            } else {
                $('#count').removeClass('d-none').find('.number').text(total_items + " items");
            }
            if (total_files == 0) {
                $('#count').removeClass('d-none').find('.totalsize').text("Zero Files");
            } else if (total_files == 1) {
                $('#count').removeClass('d-none').find('.totalsize').text(total_files + " File with Size " + total_size);
            } else {
                $('#count').removeClass('d-none').find('.totalsize').text(total_files + " Files with Size " + total_size);
            }
        }
    } catch (e) {
        console.log(e);
    }
}

/**
 * Append the data of the requested new page to the list
 * @param path
 * @param files request result
 */
function append_files_to_list(path, files) {
    const $list = $('#list');
    // Is it the last page of data?
    const is_lastpage_loaded = null === $list.data('nextPageToken');
    const is_firstpage = '0' == $list.data('curPageIndex');

    let html = "";
    const targetFiles = [];
    let totalsize = 0;
    let is_file = false;
    for (const i in files) {
        const item = files[i];
        const ep = encodeURIComponent(item.name).replace(/\//g, '%2F') + '/';
        const p = path + ep.replace(new RegExp('#', 'g'), '%23').replace(new RegExp('\\?', 'g'), '%3F');
        item['modifiedTime'] = utc2delhi(item['modifiedTime']);
        // replace / with %2F
        if (item['mimeType'] == 'application/vnd.google-apps.folder') {
            html += `<a href="${p}" style="color: ${UI.folder_text_color};" class="countitems list-group-item list-group-item-action"> ${folder_icon} ${item.name} ${UI.display_time ? `<span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</a>`;
        } else {
            totalsize = totalsize + Number(item.size);
            item['size'] = formatFileSize(item['size']);
            is_file = true;
            const epn = item.name;
            const link = UI.second_domain_for_dl ? UI.downloaddomain + item.link : window.location.origin + item.link;
            let pn = path + epn.replace(new RegExp('#', 'g'), '%23').replace(new RegExp('\\?', 'g'), '%3F');
            let c = "file";
            // README is displayed after the last page is loaded, otherwise it will affect the scroll event
            if (is_lastpage_loaded && item.name == "README.md" && UI.render_readme_md) {
                get_file(p, item, function(data) {
                    markdown("#readme_md", data);
                    $("img").addClass("img-fluid");
                });
            }
            if (item.name == "HEAD.md" && UI.render_head_md) {
                get_file(p, item, function(data) {
                    markdown("#head_md", data);
                    $("img").addClass("img-fluid");
                });
            }
            const ext = item.fileExtension;
            console.log(ext);
            //if ("|html|php|css|go|java|js|json|txt|sh|md|mp4|webm|avi|bmp|jpg|jpeg|png|gif|m4a|mp3|flac|wav|ogg|mpg|mpeg|mkv|rm|rmvb|mov|wmv|asf|ts|flv|pdf|".indexOf(`|${ext}|`) >= 0) {
            //targetFiles.push(filepath);
            pn += "?a=view";
            c += " view";
            //}
            html += `<div class="list-group-item list-group-item-action">${UI.allow_selecting_files ? '<input class="form-check-input" style="margin-top: 0.3em;margin-right: 0.5em;" type="checkbox" value="'+link+'" id="flexCheckDefault">' : ''}`;

            // Use centralized getFileIcon helper
            html += getFileIcon(ext);

            html += ` <a class="countitems size_items list-group-item-action" style="text-decoration: none; color: ${UI.css_a_tag_color};" href="${pn}">${item.name}</a>${UI.display_download ? `<a href="${link}"><svg class="float-end"width="25px" style="margin-left: 8px;" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"> <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"></path> <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"></path> </svg></a>` : ``}${UI.display_size ? `<span class="badge bg-primary float-end"> ` + item['size'] + ` </span>` : ``}${UI.display_time ? ` <span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</div>`;
        }
    }
    if (is_file && UI.allow_selecting_files) {
        document.getElementById('select_items').style.display = 'block';
    }


    /*let targetObj = {};
    targetFiles.forEach((myFilepath, myIndex) => {
        if (!targetObj[myFilepath]) {
            targetObj[myFilepath] = {
                filepath: myFilepath,
                prev: myIndex === 0 ? null : targetFiles[myIndex - 1],
                next: myIndex === targetFiles.length - 1 ? null : targetFiles[myIndex + 1],
            }
        }
    })
    // console.log(targetObj)
    if (Object.keys(targetObj).length) {
        localStorage.setItem(path, JSON.stringify(targetObj));
        // console.log(path)
    }*/

    if (targetFiles.length > 0) {
        const old = localStorage.getItem(path);
        let new_children = targetFiles;
        // Reset on page 1; otherwise append
        if (!is_firstpage && old) {
            let old_children;
            try {
                old_children = JSON.parse(old);
                if (!Array.isArray(old_children)) {
                    old_children = [];
                }
            } catch (e) {
                old_children = [];
            }
            new_children = old_children.concat(targetFiles);
        }

        localStorage.setItem(path, JSON.stringify(new_children));
    }

    // When it is page 1, remove the horizontal loading bar
    $list.html(($list.data('curPageIndex') == '0' ? '' : $list.html()) + html);
    // When it is the last page, count and display the total number of items
    if (is_lastpage_loaded) {
        const total_size = formatFileSize(totalsize) || '0 Bytes';
        const total_items = $list.find('.countitems').length;
        const total_files = $list.find('.size_items').length;
        if (total_items == 0) {
            $('#count').removeClass('d-none').find('.number').text("Empty Folder");
        } else if (total_items == 1) {
            $('#count').removeClass('d-none').find('.number').text(total_items + " item");
        } else {
            $('#count').removeClass('d-none').find('.number').text(total_items + " items");
        }
        if (total_files == 0) {
            $('#count').removeClass('d-none').find('.totalsize').text("Zero Files");
        } else if (total_files == 1) {
            $('#count').removeClass('d-none').find('.totalsize').text(total_files + " File with Size " + total_size);
        } else {
            $('#count').removeClass('d-none').find('.totalsize').text(total_files + " Files with Size " + total_size);
        }
    }
}

/**
 * Render the search results list. There is a lot of repetitive code, but there are different logics in it.
 */
function render_search_result_list() {
    const content = `
  <div class="container"><br>
  <div id="update"></div>
  <div class="container" id="select_items" style="padding: 0px 50px 10px; display:none;">
  <div class="d-flex align-items-center justify-content-between">
    <div class="form-check mr-3">
      <input class="form-check-input" style="margin-top: 0.3em;margin-right: 0.5em;" type="checkbox" id="select-all-checkboxes">
      <label class="form-check-label" for="select-all-checkboxes">Select all</label>
    </div>
    <button id="handle-multiple-items-copy" style="padding: 5px 10px; font-size: 12px;" class="btn btn-success">Copy</button>
  </div>
  </div>
  <div class="card">
  <div class="${UI.path_nav_alert_class} d-flex align-items-center" role="alert" style="margin-bottom: 0;">Search Results</div>
  <div id="list" class="list-group text-break">
  </div>
  </div>
  <div class="${UI.file_count_alert_class} text-center d-none" role="alert" id="count"><span class="number text-center"></span> | <span class="totalsize text-center"></span></div>
  <div id="readme_md" style="display:none; padding: 20px 20px;"></div>
  </div>
  `;
    $('#content').html(content);

    $('#list').html(`<div class="d-flex justify-content-center"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`);
    $('#readme_md').hide().html('');
    $('#head_md').hide().html('');

    /**
     * Callback after successful search request returns data
     * The result returned by @param res (object)
     * @param path the requested path
     * @param prevReqParams parameters used in request
     */
    function searchSuccessCallback(res, prevReqParams) {

        // Temporarily store nextPageToken and currentPageIndex in the list element
        $('#list')
            .data('nextPageToken', res['nextPageToken'])
            .data('curPageIndex', res['curPageIndex']);

        // Remove loading spinner
        $('#spinner').remove();

        if (res['nextPageToken'] === null) {
            // If it is the last page, unbind the scroll event, reset scroll_status, and append the data
            $(window).off('scroll');
            window.scroll_status.event_bound = false;
            window.scroll_status.loading_lock = false;
            append_search_result_to_list(res['data']['files']);
        } else {
            // If it is not the last page, append data and bind the scroll event (if not already bound), update scroll_status
            append_search_result_to_list(res['data']['files']);
            if (window.scroll_status.event_bound !== true) {
                // Bind event, if not yet bound
                $(window).on('scroll', function() {
                    const scrollTop = $(this).scrollTop();
                    const scrollHeight = getDocumentHeight();
                    const windowHeight = $(this).height();
                    // Roll to the bottom
                    if (scrollTop + windowHeight > scrollHeight - (Os.isMobile ? 130 : 80)) {
                        /*
     When the event of scrolling to the bottom is triggered, if it is already loading at this time, the event is ignored;
                 Otherwise, go to loading and occupy the loading lock, indicating that loading is in progress
             */
                        if (window.scroll_status.loading_lock === true) {
                            return;
                        }
                        window.scroll_status.loading_lock = true;

                        // Show a loading spinner
                        $(`<div id="spinner" class="d-flex justify-content-center"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`)
                            .insertBefore('#readme_md');

                        const $list = $('#list');
                        requestSearch({
                                q: window.MODEL.q,
                                page_token: $list.data('nextPageToken'),
                                // Request next page
                                page_index: $list.data('curPageIndex') + 1
                            },
                            searchSuccessCallback
                        );
                    }
                });
                window.scroll_status.event_bound = true;
            }
        }

        // After loading successfully and rendering new data successfully, release the loading lock so that you can continue to process the "scroll to bottom" event
        if (window.scroll_status.loading_lock === true) {
            window.scroll_status.loading_lock = false;
        }
    }

    // Start requesting data from page 1
    requestSearch({
        q: window.MODEL.q
    }, searchSuccessCallback);

    const copyBtn = document.getElementById("handle-multiple-items-copy");

    // Add a click event listener to the copy button
    copyBtn.addEventListener("click", () => {
        // Get all the checked checkboxes
        const checkedItems = document.querySelectorAll('input[type="checkbox"]:checked');

        // Create an array to store the selected items' data
        const selectedItemsData = [];
        if (checkedItems.length === 0) {
            alert("No items selected!");
            return;
        }
        // Loop through each checked checkbox
        checkedItems.forEach((item) => {
            // Get the value of the checkbox (in this case, the URL)
            const itemData = item.value;
            // Push the value to the array
            selectedItemsData.push(itemData);
        });

        // Join the selected items' data with a newline character
        const dataToCopy = selectedItemsData.join("\n");

        // Create a temporary input element
        const tempInput = document.createElement("textarea");
        tempInput.value = dataToCopy;

        // Add the temporary input element to the document
        document.body.appendChild(tempInput);

        // Select the text inside the temporary input element
        tempInput.select();

        // Copy the selected text to the clipboard
        document.execCommand("copy");

        // Remove the temporary input element from the document
        document.body.removeChild(tempInput);

        // Alert the user that the data has been copied
        alert("Selected items copied to clipboard!");
    });
}

/**
 * Append a new page of search results
 * @param files
 */
function append_search_result_to_list(files) {
    try {
        const cur = window.current_drive_order || 0;
        const $list = $('#list');
        // Is it the last page of data?
        const is_lastpage_loaded = null === $list.data('nextPageToken');
        // var is_firstpage = '0' == $list.data('curPageIndex');

        let html = "";
        let totalsize = 0;
        let is_file = false;
        for (const i in files) {
            const item = files[i];
            if (item['size'] == undefined) {
                item['size'] = "";
            }

            item['modifiedTime'] = utc2delhi(item['modifiedTime']);
            if (item['mimeType'] == 'application/vnd.google-apps.folder') {
                html += `<a style="color: ${UI.folder_text_color};" onclick="onSearchResultItemClick('${item['id']}', false)" data-bs-toggle="modal" data-bs-target="#SearchModel" class="countitems list-group-item list-group-item-action"> ${folder_icon} ${item.name} ${UI.display_time ? `<span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</a>`;
            } else {
                is_file = true;
                totalsize = totalsize + Number(item.size);
                item['size'] = formatFileSize(item['size']);
                const ext = item.fileExtension;
                const link = UI.second_domain_for_dl ? UI.downloaddomain + item.link : window.location.origin + item.link;
                html += `<div style="color: ${UI.css_a_tag_color};" gd-type="$item['mimeType']}" class="countitems size_items list-group-item list-group-item-action">${UI.allow_selecting_files ? '<input class="form-check-input" style="margin-top: 0.3em;margin-right: 0.5em;" type="checkbox" value="'+link+'" id="flexCheckDefault">' : ''}`;

                // Use centralized getFileIcon helper
                html += getFileIcon(ext);

                html += ` <span onclick="onSearchResultItemClick('${item['id']}', true)" data-bs-toggle="modal" data-bs-target="#SearchModel">${item.name}</span>${UI.display_download ? `<a href="${link}"><svg class="float-end"width="25px" style="margin-left: 8px;" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"> <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"></path> <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"></path> </svg></a>` : ``}<span class="badge float-end csize"> ${UI.display_size ? `<span class="badge bg-primary float-end"> ` + item['size'] + ` </span>` : ``}${UI.display_time ? ` <span class="badge bg-info float-end"> ` + item['modifiedTime'] + ` </span>` : ``}</div>`;

            }
        }
        if (is_file && UI.allow_selecting_files) {
            document.getElementById('select_items').style.display = 'block';
        }
        // When it is page 1, remove the horizontal loading bar
        $list.html(($list.data('curPageIndex') == '0' ? '' : $list.html()) + html);
        // When it is the last page, count and display the total number of items
        if (is_lastpage_loaded) {
            const total_size = formatFileSize(totalsize) || '0 Bytes';
            const total_items = $list.find('.countitems').length;
            const total_files = $list.find('.size_items').length;
            if (total_items == 0) {
                $('#count').removeClass('d-none').find('.number').text("No Results");
            } else if (total_items == 1) {
                $('#count').removeClass('d-none').find('.number').text(total_items + " item");
            } else {
                $('#count').removeClass('d-none').find('.number').text(total_items + " items");
            }
            if (total_files == 0) {
                $('#count').removeClass('d-none').find('.totalsize').text("Found Nothing");
            } else if (total_files == 1) {
                $('#count').removeClass('d-none').find('.totalsize').text(total_files + " File with Size " + total_size);
            } else {
                $('#count').removeClass('d-none').find('.totalsize').text(total_files + " Files with Size " + total_size);
            }
        }
    } catch (e) {
        console.log(e);
    }
}

/**
 * Search result item click event
 * @param a_ele Clicked element
 */
function onSearchResultItemClick(file_id, can_preview) {
    const cur = window.current_drive_order;
    let title = `Loading...`;
    $('#SearchModelLabel').html(title);
    let content = `<div class="d-flex justify-content-center"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div>`;
    $('#modal-body-space').html(content);
    const p = {
        id: file_id
    };
    // Request a path
    fetch(`/${cur}:id2path`, {
            method: 'POST',
            body: JSON.stringify(p),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        })
        .then(function(response) {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Request failed.');
            }
        })
        .then(function(obj) {
            const href = `${obj.path}`;
            const encodedUrl = href.replace(new RegExp('#', 'g'), '%23').replace(new RegExp('\\?', 'g'), '%3F');
            title = `Result`;
            $('#SearchModelLabel').html(title);
            content = `<a class="btn btn-info" href="${encodedUrl}${can_preview ? '?a=view' : ''}">Open</a> <a class="btn btn-secondary" href="${encodedUrl}${can_preview ? '?a=view' : ''}" target="_blank">Open in New Tab</a>`;
            $('#modal-body-space').html(content);
        })
        .catch(function(error) {
            console.log(error);
            const link = "";
            title = `Fallback Method`;
            $('#SearchModelLabel').html(title);
            content = `<a class="btn btn-info" href="/fallback?id=${file_id}&${can_preview ? 'a=view' : ''}">Open</a> <a class="btn btn-secondary" href="/fallback?id=${file_id}&${can_preview ? 'a=view' : ''}" target="_blank">Open in New Tab</a>`;
            $('#modal-body-space').html(content);
        });
}

function get_file(path, file, callback) {
    const key = "file_path_" + path + file['modifiedTime'];
    const data = localStorage.getItem(key);
    if (data != undefined) {
        return callback(data);
    } else {
        $.get(path, function(d) {
            localStorage.setItem(key, d);
            callback(d);
        });
    }
}

async function fallback(id, type) {
    if (type) { // is a file id
        const cookie_folder_id = await getCookie("root_id") || '';
        $('#content').html(`<div class="d-flex justify-content-center" style="height: 150px"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`);
        fetch("/0:fallback", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    id
                }),
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error("Request failed");
                }
                return response.json();
            })
            .then(function(obj) {
                console.log(obj);
                const mimeType = obj.mimeType;
                const fileExtension = obj.fileExtension;
                const code = ["php", "css", "go", "java", "js", "json", "txt", "sh", "md", "html", "xml", "py", "rb", "c", "cpp", "h", "hpp"];
                const video = ["mp4", "webm", "avi", "mpg", "mpeg", "mkv", "rm", "rmvb", "mov", "wmv", "asf", "ts", "flv", "3gp", "m4v"];
                const audio = ["mp3", "flac", "wav", "ogg", "m4a", "aac", "wma", "alac"];
                const image = ["bmp", "jpg", "jpeg", "png", "gif", "svg", "tiff", "ico"];
                const pdf = ["pdf"];
                if (mimeType === "application/vnd.google-apps.folder") {
                    window.location.href = window.location.pathname + "/";
                } else if (fileExtension) {
                    const name = obj.name;
                    const encoded_name = encodeURIComponent(name);
                    const size = formatFileSize(obj.size);
                    const url = UI.second_domain_for_dl ? UI.downloaddomain + obj.link : window.location.origin + obj.link;
                    const file_id = obj.id;
                    if (mimeType.includes("video") || video.includes(fileExtension)) {
                        const poster = obj.thumbnailLink ? obj.thumbnailLink.replace("s220", "s0") : UI.poster;
                        file_video(name, encoded_name, size, poster, url, mimeType, file_id, cookie_folder_id);
                    } else if (mimeType.includes("audio") || audio.includes(fileExtension)) {
                        file_audio(name, encoded_name, size, url, file_id, cookie_folder_id);
                    } else if (mimeType.includes("image") || image.includes(fileExtension)) {
                        file_image(name, encoded_name, size, url, file_id, cookie_folder_id);
                    } else if (mimeType.includes("pdf") || pdf.includes(fileExtension)) {
                        file_pdf(name, encoded_name, size, url, file_id, cookie_folder_id);
                    } else if (code.includes(fileExtension)) {
                        file_code(name, encoded_name, size, url, file_id, cookie_folder_id);
                    } else {
                        file_others(name, encoded_name, size, url, file_id, cookie_folder_id);
                    }
                }
            })
            .catch(function(error) {
                const content = `
          <div class="container"><br>
          <div class="card text-center">
            <div class="card-body text-center">
              <div class="${UI.file_view_alert_class}" id="file_details" role="alert"><b>404.</b> That’s an error. ` + error + `</div>
            </div>
            <p>The requested URL was not found on this server. That’s all we know.</p>
            <div class="card-text text-center">
              <div class="btn-group text-center">
                <a href="/" type="button" class="btn btn-primary">Homepage</a>
              </div>
            </div><br>
          </div>
        </div>`;
                $("#content").html(content);
            });
    } else { // is a folder id
        return list(id, true);
    }
}

// File display ?a=view
async function file(path) {
    const cookie_folder_id = await getCookie("root_id") || '';
    const name = path.split('/').pop();
    $('#content').html(`<div class="d-flex justify-content-center" style="height: 150px"><div class="spinner-border ${UI.loading_spinner_class} m-5" role="status" id="spinner"><span class="sr-only"></span></div></div>`);
    fetch("", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                path: path
            }),
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error("Request failed");
            }
            return response.json();
        })
        .then(function(obj) {
            console.log(obj);
            const mimeType = obj.mimeType;
            const fileExtension = obj.fileExtension;
            const code = ["php", "css", "go", "java", "js", "json", "txt", "sh", "md", "html", "xml", "py", "rb", "c", "cpp", "h", "hpp"];
            const video = ["mp4", "webm", "avi", "mpg", "mpeg", "mkv", "rm", "rmvb", "mov", "wmv", "asf", "ts", "flv", "3gp", "m4v"];
            const audio = ["mp3", "flac", "wav", "ogg", "m4a", "aac", "wma", "alac"];
            const image = ["bmp", "jpg", "jpeg", "png", "gif", "svg", "tiff", "ico"];
            const pdf = ["pdf"];
            if (mimeType === "application/vnd.google-apps.folder") {
                window.location.href = window.location.pathname + "/";
            } else if (fileExtension) {
                const name = obj.name;
                const encoded_name = encodeURIComponent(name);
                const size = formatFileSize(obj.size);
                const url = UI.second_domain_for_dl ? UI.downloaddomain + obj.link : window.location.origin + obj.link;
                const file_id = obj.id;
                if (mimeType.includes("video") || video.includes(fileExtension)) {
                    const poster = obj.thumbnailLink ? obj.thumbnailLink.replace("s220", "s0") : UI.poster;
                    file_video(name, encoded_name, size, poster, url, mimeType, file_id, cookie_folder_id);
                } else if (mimeType.includes("audio") || audio.includes(fileExtension)) {
                    file_audio(name, encoded_name, size, url, file_id, cookie_folder_id);
                } else if (mimeType.includes("image") || image.includes(fileExtension)) {
                    file_image(name, encoded_name, size, url, file_id, cookie_folder_id);
                } else if (mimeType.includes("pdf") || pdf.includes(fileExtension)) {
                    file_pdf(name, encoded_name, size, url, file_id, cookie_folder_id);
                } else if (code.includes(fileExtension)) {
                    file_code(name, encoded_name, size, url, file_id, cookie_folder_id);
                } else {
                    file_others(name, encoded_name, size, url, file_id, cookie_folder_id);
                }
            }
        })
        .catch(function(error) {
            const content = `
          <div class="container"><br>
          <div class="card text-center">
            <div class="card-body text-center">
              <div class="${UI.file_view_alert_class}" id="file_details" role="alert"><b>404.</b> That’s an error. ` + error + `</div>
            </div>
            <p>The requested URL was not found on this server. That’s all we know.</p>
            <div class="card-text text-center">
              <div class="btn-group text-center">
                <a href="/" type="button" class="btn btn-primary">Homepage</a>
              </div>
            </div><br>
          </div>
        </div>`;
            $("#content").html(content);
        });
}
// Document display |zip|.exe/others direct downloads
function file_others(name, encoded_name, size, url, file_id, cookie_folder_id) {
    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }

    // Add the container and card elements
    const content = `
    <div class="container"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
            <div class="card text-center">
            <div class="card-body text-center">
              <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
            </div>
            <div class="card-body">
            <div class="input-group mb-4">
              <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
            </div>
            <div class="card-text text-center">
            <div class="btn-group text-center">
                <a href="${url}" type="button" class="btn btn-primary">Download</a>
                <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  <span class="sr-only"></span>
                </button>
                <div class="dropdown-menu">
                  <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
                  <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
                  <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
                </div>
            </div>
            </div>
            <br></div>`;
    $("#content").html(content);
}

function file_code(name, encoded_name, size, bytes, url, ext, file_id, cookie_folder_id) {
    const type = {
        "html": "html",
        "php": "php",
        "css": "css",
        "go": "golang",
        "java": "java",
        "js": "javascript",
        "json": "json",
        "txt": "Text",
        "sh": "sh",
        "md": "Markdown",
    };

    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }

    // Add the container and card elements
    const content = `
    <div class="container"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
      <div class="card text-center">
        <div class="card-body text-center">
          <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
        </div>
        <div id="code_spinner"></div>` +
        (UI.second_domain_for_dl ? `` : `<pre class="line-numbers language-markup" data-src="plugins/line-numbers/index.html" data-start="-5" style="white-space: pre-wrap; counter-reset: linenumber -6;" data-src-status="loaded" tabindex="0"><code id="editor"></code></pre>`) +
        `<div class="card-body">
          <div class="input-group mb-4">
            <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
          </div>
          <div class="card-text text-center">
            <div class="btn-group text-center">
              <a href="${url}" type="button" class="btn btn-primary">Download</a>
              <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <span class="sr-only"></span>
              </button>
              <div class="dropdown-menu">
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
              </div>
            </div>
          </div>
          <br>
        </div>
      </div>
    </div>`;

    $('#content').html(content);
    const spinner = '<div class="d-flex justify-content-center"><div class="spinner-border m-5" role="status"><span class="sr-only"></span></div></div>';
    $("#code_spinner").html(spinner);
    if (bytes <= 1024 * 1024 * 2) {
        $.get(url, function(data) {
            $('#editor').html($('<div/>').text(data).html());
            $("#code_spinner").html("");
            let code_type = "Text";
            if (type[ext] != undefined) {
                code_type = type[ext];
            }
        });
    } else {
        $("#code_spinner").html("");
        $('#editor').html(`<div class="${UI.file_view_alert_class}" id="file_details" role="alert">File size is too large to preview, Max Limit is 2 MB</div>`);
    }
}



// Document display video |mp4|webm|avi|
function file_video(name, encoded_name, size, poster, url, mimeType, file_id, cookie_folder_id) {
    const url_base64 = btoa(url);
    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }
    let player;
    let player_js = '';
    let player_css = '';
    if (!UI.disable_player) {
        if (player_config.player == "plyr") {
            player = `<video id="player" playsinline controls data-poster="${poster}">
      <source src="${url}" type="video/mp4" />
      <source src="${url}" type="video/webm" />
        </video>`;
            player_js = 'https://cdn.plyr.io/' + player_config.plyr_io_version + '/plyr.polyfilled.js';
            player_css = 'https://cdn.plyr.io/' + player_config.plyr_io_version + '/plyr.css';
        } else if (player_config.player == "videojs") {
            player = `<video id="vplayer" poster="${poster}" muted=true class="video-js vjs-default-skin" controls preload="auto" width="100%" height="100%" data-setup='{"fluid": true}' style="--plyr-captions-text-color: #ffffff;--plyr-captions-background: #000000;">
      <source src="${url}" type="video/mp4" />
      <source src="${url}" type="video/webm" />
      <source src="${url}" type="video/avi" />
    </video>`;
            player_js = 'https://vjs.zencdn.net/' + player_config.videojs_version + '/video.js';
            player_css = 'https://vjs.zencdn.net/' + player_config.videojs_version + '/video-js.css';
        } else if (player_config.player == "dplayer") {
            player = `<div id="player-container"></div>`;
            player_js = 'https://cdn.jsdelivr.net/npm/dplayer/dist/DPlayer.min.js';
            player_css = 'https://cdn.jsdelivr.net/npm/dplayer/dist/DPlayer.min.css';
        } else if (player_config.player == "jwplayer") {
            player = `<div id="player"></div>`;
            player_js = 'https://content.jwplatform.com/libraries/IDzF9Zmk.js';
            player_css = '';
        }
    }
    // Add the container and card elements
    const content = `
    <div class="container text-center"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
      <div class="card text-center">
        <div class="text-center">
          <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>${player}</div>
        </br>
        ${UI.disable_video_download ? `` : `
          <div class="card-body">
          <div class="input-group mb-4">
          <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
          </div>
          <div class="btn-group text-center">
              <a href="${url}" type="button" class="btn btn-primary">Download</a>
              <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <span class="sr-only"></span>
              </button>
              <div class="dropdown-menu">
              <a class="dropdown-item" href="iina://weblink?url=${url}">IINA</a>
              <a class="dropdown-item" href="potplayer://${url}">PotPlayer</a>
              <a class="dropdown-item" href="vlc://${url}">VLC Mobile</a>
              <a class="dropdown-item" href="${url}">VLC Desktop</a>
              <a class="dropdown-item" href="nplayer-${url}">nPlayer</a>
              <a class="dropdown-item" href="intent://${url}#Intent;type=video/any;package=is.xyz.mpv;scheme=https;end;">mpv-android</a>
              <a class="dropdown-item" href="mpv://${url_base64}">mpv x64</a>
              <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.ad;S.title=${encoded_name};end">MX Player (Free)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.pro;S.title=${encoded_name};end">MX Player (Pro)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
              </div>
          </div>          
          </div>
          </div>
          `}
      </div>
    </div>
  `;
    $("#content").html(content);

    // Load Video.js and initialize the player
    const videoJsScript = document.createElement('script');
    videoJsScript.src = player_js;
    videoJsScript.onload = function() {
        // Video.js is loaded, initialize the player
        if (player_config.player == "plyr") {
            const player = new Plyr('#player');
        } else if (player_config.player == "videojs") {
            const player = new videojs('vplayer');
        } else if (player_config.player == "dplayer") {
            const dp = new DPlayer({
                container: document.getElementById('player-container'),
                screenshot: true,
                video: {
                    url: url,
                    pic: poster,
                    thumbnails: poster,
                },
            });
        } else if (player_config.player == "jwplayer") {
            jwplayer("player").setup({
                file: url,
                type: mimeType,
                autostart: false,
                image: poster,
                width: "100%",
                aspectratio: "16:9",
                title: name,
                description: "Powered by Google Drive Index",
                tracks: [{
                    file: url,
                    kind: "captions",
                    label: "Default",
                    "default": true,
                }],
                captions: {
                    color: "#f3f378",
                    fontSize: 14,
                    backgroundOpacity: 50,
                    edgeStyle: "raised",
                },
            });
        }

    };
    document.head.appendChild(videoJsScript);

    const videoJsStylesheet = document.createElement('link');
    videoJsStylesheet.href = player_css;
    videoJsStylesheet.rel = 'stylesheet';
    document.head.appendChild(videoJsStylesheet);
}


// File display Audio |mp3|flac|m4a|wav|ogg|
function file_audio(name, encoded_name, size, url, file_id, cookie_folder_id) {
    const url_base64 = btoa(url);
    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }

    // Add the container and card elements
    const content = `
    <div class="container text-center"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
      <div class="card text-center">
        <div class="text-center">
          <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
          ${UI.disable_player ? `` : `
          <video id="aplayer" poster="${UI.audioposter}" muted=true class="video-js vjs-default-skin" controls preload="auto" width="100%" height="100%" data-setup='{"fluid": true}' style="--plyr-captions-text-color: #ffffff;--plyr-captions-background: #000000;">
            <source src="${url}" type="audio/mpeg" />
            <source src="${url}" type="audio/ogg" />
            <source src="${url}" type="audio/wav" />
          </video>`}
        </div>
        </br>
        ${UI.disable_audio_download ? `` : `
          <div class="card-body">
          <div class="input-group mb-4">
          <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
          </div>
          <div class="btn-group text-center">
              <a href="${url}" type="button" class="btn btn-primary">Download</a>
              <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <span class="sr-only"></span>
              </button>
              <div class="dropdown-menu">
              <a class="dropdown-item" href="iina://weblink?url=${url}">IINA</a>
              <a class="dropdown-item" href="potplayer://${url}">PotPlayer</a>
              <a class="dropdown-item" href="vlc://${url}">VLC Mobile</a>
              <a class="dropdown-item" href="${url}">VLC Desktop</a>
              <a class="dropdown-item" href="nplayer-${url}">nPlayer</a>
              <a class="dropdown-item" href="intent://${url}#Intent;type=audio/any;package=is.xyz.mpv;scheme=https;end;">mpv-android</a>
              <a class="dropdown-item" href="mpv://${url_base64}">mpv x64</a>
              <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.ad;S.title=${encoded_name};end">MX Player (Free)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;package=com.mxtech.videoplayer.pro;S.title=${encoded_name};end">MX Player (Pro)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
              <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
              </div>
          </div>
          <br>
          </div>
          </div>
          `}
      </div>
    </div>
  `;
    $("#content").html(content);

    // Load Video.js and initialize the player
    const videoJsScript = document.createElement('script');
    videoJsScript.src = 'https://vjs.zencdn.net/' + UI.videojs_version + '/video.min.js';
    videoJsScript.onload = function() {
        // Video.js is loaded, initialize the player
        const player = videojs('aplayer');
    };
    document.head.appendChild(videoJsScript);

    const videoJsStylesheet = document.createElement('link');
    videoJsStylesheet.href = 'https://vjs.zencdn.net/' + UI.videojs_version + '/video-js.css';
    videoJsStylesheet.rel = 'stylesheet';
    document.head.appendChild(videoJsStylesheet);
}



// Document display pdf
function file_pdf(name, encoded_name, size, url, file_id, cookie_folder_id) {
    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }

    // Add the container and card elements
    const content = `
    <div class="container text-center"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
    <div class="card">
    <div class="card-body text-center">
    <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
    <div>
    </div><br>
    <iframe src="https://docs.google.com/gview?url=${encodeURIComponent(url)}&embedded=true" style="width:100%; height:500px;" frameborder="0"></iframe>
    </div>
    <div class="card-body">
    <div class="input-group mb-4">
    <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
    </div>
    <div class="card-text text-center">
    <div class="btn-group text-center">
        <a href="${url}" type="button" class="btn btn-primary">Download</a>
        <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
            <span class="sr-only"></span>
        </button>
        <div class="dropdown-menu">
            <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
            <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
            <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
        </div>
    </div>
    </div>
    <br>
    
    </div>
    </div>
    </div>  
  `;
    $("#content").html(content);
}

// image display
function file_image(name, encoded_name, size, url, file_id, cookie_folder_id) {
    // Split the file path into parts
    const path = window.location.pathname;
    const pathParts = path.split('/');
    // Generate the navigation based on path parts
    let navigation = '';
    let new_path = '';
    for (let i = 0; i < pathParts.length; i++) {
        let part = pathParts[i];
        if (i == pathParts.length - 1) {
            new_path += part + '?a=view';
        } else {
            new_path += part + '/';
        }
        if (part.length > 15) {
            part = decodeURIComponent(part);
            part = part.substring(0, 10) + '...';
        }
        if (part == '') {
            part = 'Home';
        }
        navigation += '<a href="' + new_path + '" class="breadcrumb-item">' + part + '</a>';
    }

    // Add the container and card elements // wait until image is loaded and then hide spinner
    const content = `
    <div class="container text-center"><br>
      <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
          ${navigation}
        </ol>
      </nav>
      <div class="card">
        <div class="card-body text-center">
          <div class="${UI.file_view_alert_class}" id="file_details" role="alert">${name}<br>${size}</div>
          <img src="${url}" id="load_image" width="100%">
        </div>
        <div class="card-body">
          <div class="input-group mb-4">
            <div class="input-group-prepend">
              <span class="input-group-text" id="">Full URL</span>
            </div>
            <input type="text" class="form-control" id="dlurl" value="${url}" readonly>
          </div>
          <div class="card-text text-center">
            <div class="btn-group text-center">
              <a href="${url}" type="button" class="btn btn-primary">Download</a>
              <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <span class="sr-only"></span>
              </button>
              <div class="dropdown-menu">
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Free)</a>
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.adm.lite/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM (Lite)</a>
                <a class="dropdown-item" href="intent:${url}#Intent;component=idm.internet.download.manager.plus/idm.internet.download.manager.Downloader;S.title=${encoded_name};end">1DM+ (Plus)</a>
              </div>
            </div>
          </div>
          <br>
        </div>
      </div>
    </div>
  `;
    $('#content').html(content);
}

// Time conversion
function utc2delhi(utc_datetime) {
    // Convert UTC datetime to local Delhi time
    const utcDate = new Date(utc_datetime);
    const delhiDate = new Date(utcDate.getTime() + 5.5 * 60 * 60 * 1000);

    // Format the Delhi date and time
    const year = delhiDate.getFullYear();
    const month = ('0' + (delhiDate.getMonth() + 1)).slice(-2);
    const date = ('0' + delhiDate.getDate()).slice(-2);
    const hour = ('0' + delhiDate.getHours()).slice(-2);
    const minute = ('0' + delhiDate.getMinutes()).slice(-2);
    const second = ('0' + delhiDate.getSeconds()).slice(-2);

    return `${date}-${month}-${year} ${hour}:${minute}:${second}`;
}


// bytes adaptive conversion to KB, MB, GB
function formatFileSize(bytes) {
    if (bytes >= 1099511627776) {
        bytes = (bytes / 1099511627776).toFixed(2) + ' TB';
    } else if (bytes >= 1073741824) {
        bytes = (bytes / 1073741824).toFixed(2) + ' GB';
    } else if (bytes >= 1048576) {
        bytes = (bytes / 1048576).toFixed(2) + ' MB';
    } else if (bytes >= 1024) {
        bytes = (bytes / 1024).toFixed(2) + ' KB';
    } else if (bytes > 1) {
        bytes = bytes + ' bytes';
    } else if (bytes === 1) {
        bytes = bytes + ' byte';
    } else {
        bytes = '';
    }
    return bytes;
}


String.prototype.trim = function(char) {
    if (char) {
        return this.replace(new RegExp('^\\' + char + '+|\\' + char + '+$', 'g'), '');
    }
    return this.replace(/^\s+|\s+$/g, '');
};


// README.md HEAD.md support
function markdown(el, data) {
    const html = marked.parse(data);
    $(el).show().html(html);
}

// Listen for fallback events
window.onpopstate = function() {
    const path = window.location.pathname;
    render(path);
};

$(function() {
    init();
    const path = window.location.pathname;
    /*$("body").on("click", '.folder', function () {
        var url = $(this).attr('href');
        history.pushState(null, null, url);
        render(url);
        return false;
    });
    $("body").on("click", '.view', function () {
        var url = $(this).attr('href');
        history.pushState(null, null, url);
        render(url);
        return false;
    });*/

    render(path);
});

// Copy to Clipboard for Direct Links, This will be modified soon with other UI
function copyFunction() {
    const copyText = document.getElementById("dlurl");
    copyText.select();
    copyText.setSelectionRange(0, 99999);

    navigator.clipboard.writeText(copyText.value)
        .then(function() {
            const tooltip = document.getElementById("myTooltip");
            tooltip.innerHTML = "Copied";
        })
        .catch(function(error) {
            console.error("Failed to copy text: ", error);
        });
}

function outFunc() {
    const tooltip = document.getElementById("myTooltip");
    tooltip.innerHTML = "Copy";
}

// function to update the list of checkboxes
function updateCheckboxes() {
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    const selectAllCheckbox = document.getElementById('select-all-checkboxes');

    if (checkboxes.length > 0 && selectAllCheckbox) { // Check if checkboxes and selectAllCheckbox exist
        selectAllCheckbox.addEventListener('click', () => {
            checkboxes.forEach((checkbox) => {
                checkbox.checked = selectAllCheckbox.checked;
            });
        });
    }
}

async function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// Copy File to User Drive
async function copyFile(driveid) {
    try {
        const copystatus = document.getElementById('copystatus');
        copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Processing... </div>`;

        const user_folder_id = document.getElementById('user_folder_id').value;
        if (user_folder_id === '') {
            copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Empty ID </div>`;
            return null;
        }

        document.getElementById('spinner').style.display = 'block';
        document.cookie = `root_id=${user_folder_id}; expires=Thu, 18 Dec 2050 12:00:00 UTC`;
        const time = Math.floor(Date.now() / 1000);
        const response = await fetch('/copy', {
            method: 'POST',
            cache: 'no-cache',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `id=${encodeURIComponent(driveid)}&root_id=${user_folder_id}&resourcekey=null&time=${time}`
        });

        if (response.status === 500) {
            copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Unable to Copy File, Make Sure you've added system@zindex.eu.org to your Destination Folder </div>`;
        } else if (response.status === 401) {
            copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Unauthorized </div>`;
        } else if (response.ok) {
            const data = await response.json();
            if (data && data.name) {
                const link = `https://drive.google.com/file/d/${data.id}/view?usp=share_link`;
                const copyresult = document.getElementById('copyresult');
                copyresult.innerHTML = `<div class="col-12 col-md-12"> <input type="text" id="usercopiedfile" class="form-control" placeholder="Enter Your Folder ID to Copy this File" value="${link}" readonly></div> <div class="col-12 col-md-12"> <a href="${link}" target="_blank" style="margin-top: 5px;" class="btn btn-danger btn-block">Open Copied File</a></div>`;
            } else if (data && data.error && data.error.message) {
                copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> ` + data.error.message + ` </div>`;
            } else {
                copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Unable to Copy File </div>`;
            }
        } else {
            copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> Unable to Copy File </div>`;
        }

        document.getElementById('spinner').style.display = 'none';
    } catch (error) {
        const copystatus = document.getElementById('copystatus');
        copystatus.innerHTML = `<div class='alert alert-danger' role='alert'> An error occurred ` + error + `</div>`;
        document.getElementById('spinner').style.display = 'none';
    }
}


// create a MutationObserver to listen for changes to the DOM
const observer = new MutationObserver(() => {
    updateCheckboxes();
});

// define the options for the observer (listen for changes to child elements)
const options = {
    childList: true,
    subtree: true
};

// observe changes to the body element
observer.observe(document.documentElement, options);