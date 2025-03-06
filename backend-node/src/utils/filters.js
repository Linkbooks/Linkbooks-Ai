/**
 * Formats a datetime string.
 * @param {string} value - ISO datetime string.
 * @param {string} format - Desired output format.
 * @returns {string} - Formatted date string.
 */
const datetimeFormat = (value, format = "YYYY-MM-DD HH:mm:ss") => {
    if (!value) return "N/A";
    return new Date(value).toLocaleString("en-GB", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };
  
  module.exports = { datetimeFormat };
  