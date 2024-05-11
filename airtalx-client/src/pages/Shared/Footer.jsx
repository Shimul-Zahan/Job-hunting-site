import { Link } from "react-router-dom";
import { FaFacebookF, FaInstagram, FaLinkedinIn, FaTwitter, FaYoutube } from "react-icons/fa";

const Footer = () => {
    return (
        <div>
            <div className="flex-grow bg-[#2792a8] text-white py-4">
                <div className="lg:w-3/4 w-11/12 mx-auto">
                    <div className="md:flex md:justify-between grid grid-cols-2 gap-8">
                        <div>
                            <h6 className="font-semibold uppercase pb-2">Services</h6>
                            <div className="flex flex-col">
                                <Link to={'/findJob'}>Find Job</Link>
                                <Link to={'/findEmploye'}>Find Employee</Link>
                            </div>
                        </div>
                        <div>
                            <h6 className="font-semibold uppercase pb-2">Company</h6>
                            <div className="flex flex-col">
                                <Link to={'/aboutUs'}>About Us</Link>
                                <Link to={'/contactus'}>Contact Us</Link>
                                <Link to={'/blogs'}>Blogs</Link>
                            </div>
                        </div>
                        <div>
                            <h6 className="font-semibold uppercase pb-2">Legal</h6>
                            <div className="flex flex-col">
                                <Link to={'/termsOfUse'}>Terms of Use</Link>
                                <Link to={'/privacyAndPolicy'}>Privacy & Policy</Link>
                                <Link to={'/helpAndFAQs'}>Help and FAQs</Link>
                            </div>
                        </div>
                        <div className="">
                            <h6 className="font-semibold uppercase pb-2">Social Links</h6>
                            <div className="flex gap-2 flex-wrap">
                                <Link className="bg-[#153147] rounded-full p-2"><FaFacebookF /></Link>
                                <Link className="bg-[#153147] rounded-full p-2"><FaInstagram /></Link>
                                <Link className="bg-[#153147] rounded-full p-2"><FaTwitter /></Link>
                                <Link className="bg-[#153147] rounded-full p-2"><FaLinkedinIn /></Link>
                                <Link className="bg-[#153147] rounded-full p-2"><FaYoutube /></Link>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div className="bg-[#1b405d] text-white p-3">
                <div>
                    <p className="text-center">Copyright © 2024 - All right reserved by airTalX</p>
                </div>
            </div>
        </div>
    );
};

export default Footer;
